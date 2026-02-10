<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Str;
use Firebase\JWT\JWT;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use App\Services\FmsClient;
use App\Models\MfaChallenge;
use Illuminate\Support\Facades\Mail;

class LoginController extends Controller
{
    public function login(Request $request, FmsClient $fms)
    {
        $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required', 'string', 'min:6'],
            'device_id' => ['required', 'string', 'max:128'],
            'lat' => ['nullable', 'numeric'],
            'lon' => ['nullable', 'numeric'],
        ]);

        $email = $request->input('email');
        $password = $request->input('password');

        $deviceId = $request->input('device_id');
        $lat = $request->input('lat');
        $lon = $request->input('lon');

        $correlationId =
            $request->header('X-Correlation-ID')
            ?? $request->header('X-Request-ID')
            ?? (string) Str::uuid();

        // prefer x-forwarded-for if present
        $ip = $request->header('X-Forwarded-For');
        if ($ip) {
            $ip = trim(explode(',', $ip)[0]);
        } else {
            $ip = $request->ip();
        }

        $userAgent = (string) $request->userAgent();

        $user = User::where('email', $email)->first();
        $userIdOrNull = $user ? (int) $user->id : null;

        /**
         * Exactly ONE FMS post per login request.
         * - wrong password => one FMS call with success=false
         * - correct password => one FMS call with success=true
         */

        // Wrong credentials path
        if (!$user || !Hash::check($password, $user->password)) {
            $payload = [
                'correlation_id' => $correlationId,
                'user_id' => $userIdOrNull,
                'identifier' => $email,
                'device_id' => $deviceId,
                'ip' => $ip,
                'user_agent' => $userAgent,
                'success' => false,
                'lat' => $lat,
                'lon' => $lon,
                'occurred_at' => now()->toIso8601String(),
            ];

            $fmsRes = null;
            try { $fmsRes = $fms->evaluateLoginAttempt($payload); } catch (\Throwable $e) { $fmsRes = null; }

            // Enforce BLOCK even on invalid credentials (lockout)
            if ($fmsRes && ($fmsRes['ok'] ?? false) && is_array($fmsRes['json'] ?? null)) {
                $decision = $fmsRes['json']['decision'] ?? null;
                if ($decision === 'BLOCK') {
                    return response()->json([
                        'message' => 'login blocked by risk policy',
                        'decision' => 'BLOCK',
                        'triggered_rules' => $fmsRes['json']['triggered_rules'] ?? [],
                        'expires_in' => $fmsRes['json']['expires_in'] ?? null,
                        'correlation_id' => $correlationId,
                    ], 403);
                }
            }

            return response()->json(['message' => 'invalid credentials'], 401);
        }

        // Correct credentials path
        $userId = (int) $user->id;

        $fmsPayload = [
            'correlation_id' => $correlationId,
            'user_id' => $userId,
            'identifier' => $email,
            'device_id' => $deviceId,
            'ip' => $ip,
            'user_agent' => $userAgent,
            'success' => true,
            'lat' => $lat,
            'lon' => $lon,
            'occurred_at' => now()->toIso8601String(),
        ];

        $fmsRes = null;
        try { $fmsRes = $fms->evaluateLoginAttempt($fmsPayload); } catch (\Throwable $e) { $fmsRes = null; }

        $decision = 'STEP_UP'; // fail-safe
        $triggeredRules = [];
        $expiresIn = null;

        if ($fmsRes && ($fmsRes['ok'] ?? false) && is_array($fmsRes['json'] ?? null)) {
            $decision = $fmsRes['json']['decision'] ?? 'STEP_UP';
            $triggeredRules = $fmsRes['json']['triggered_rules'] ?? [];
            $expiresIn = $fmsRes['json']['expires_in'] ?? null;
        }

        if ($decision === 'BLOCK') {
            return response()->json([
                'message' => 'login blocked by risk policy',
                'decision' => 'BLOCK',
                'triggered_rules' => $triggeredRules,
                'expires_in' => $expiresIn,
                'correlation_id' => $correlationId,
            ], 403);
        }

        if ($decision === 'STEP_UP') {
            $otp = (string) random_int(100000, 999999);

            $challenge = MfaChallenge::create([
                'id' => (string) Str::uuid(),
                'user_id' => $userId,
                'purpose' => 'login_step_up',
                'otp_hash' => Hash::make($otp),
                'expires_at' => now()->addMinutes(5),
                'attempts' => 0,
                'status' => 'pending',
                'device_id' => $deviceId,
                'correlation_id' => substr($correlationId, 0, 64),
            ]);

            Mail::raw(
                "Your OTP code is: {$otp}\n\nIt expires in 5 minutes.\n\nIf you didn't request this, ignore this email.",
                function ($message) use ($user) {
                    $message->to($user->email)->subject('Your MFA OTP Code');
                }
            );


            $debugOtp = filter_var(env('MFA_DEBUG_RETURN_OTP', false), FILTER_VALIDATE_BOOL);

            $resp = [
                'mfa_required' => true,
                'challenge_id' => $challenge->id,
                'expires_in' => 300,
                'decision' => 'STEP_UP',
                'triggered_rules' => $triggeredRules,
                'correlation_id' => $correlationId,
            ];

            if ($debugOtp) $resp['debug_otp'] = $otp;

            return response()->json($resp, 200);
        }

        // ALLOW => issue opaque session, store JWT in Redis
        $opaque = 'opaque_' . Str::random(48);

        $secret = env('JWT_SECRET');
        if (!$secret) {
            return response()->json(['message' => 'JWT_SECRET not set'], 500);
        }

        $ttlSeconds = (int) env('JWT_TTL_SECONDS', 900);
        $now = time();

        $issuer = env('JWT_ISSUER', 'auth-service');
        $aud = env('JWT_AUDIENCE', 'banking-gateway');

        $payload = [
            'typ' => 'access',
            'iss' => $issuer,
            'aud' => $aud,
            'sub' => $userId,
            'iat' => $now,
            'nbf' => $now - 5,
            'exp' => $now + $ttlSeconds,
            'jti' => (string) Str::uuid(),
            'sid' => $opaque,
        ];

        $jwt = JWT::encode($payload, $secret, 'HS256');
        Redis::setex("opaque:token:{$opaque}", $ttlSeconds, $jwt);

        return response()->json([
            'access_token' => $opaque,
            'token_type' => 'Bearer',
            'expires_in' => $ttlSeconds,
            'user' => [
                'id' => $user->id,
                'email' => $user->email,
                'name' => $user->name,
            ],
        ]);
    }
}
