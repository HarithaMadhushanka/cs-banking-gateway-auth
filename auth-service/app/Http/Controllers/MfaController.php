<?php

namespace App\Http\Controllers;

use App\Models\MfaChallenge;
use App\Services\FmsClient;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Str;
use Firebase\JWT\JWT;

class MfaController extends Controller
{
    public function verify(Request $request, FmsClient $fms)
    {
        $data = $request->validate([
            'challenge_id' => ['required', 'uuid'],
            'otp' => ['required', 'string', 'min:4', 'max:10'],
        ]);

        $challenge = MfaChallenge::where('id', $data['challenge_id'])->first();
        if (!$challenge) return response()->json(['message' => 'invalid challenge'], 404);

        if ($challenge->status !== 'pending') {
            return response()->json(['message' => 'challenge not pending'], 400);
        }

        if (now()->greaterThan($challenge->expires_at)) {
            $challenge->status = 'expired';
            $challenge->save();
            return response()->json(['message' => 'challenge expired'], 400);
        }

        if ($challenge->attempts >= 5) {
            $challenge->status = 'locked';
            $challenge->save();
            return response()->json(['message' => 'challenge locked'], 429);
        }

        $challenge->attempts += 1;

        if (!Hash::check($data['otp'], $challenge->otp_hash)) {
            $challenge->save();
            return response()->json(['message' => 'invalid otp'], 401);
        }

        // Mark verified
        $challenge->status = 'verified';
        $challenge->save();

        // After MFA success, tell FMS to trust device (mfa_verified=true)
        $correlationId = $challenge->correlation_id;
        $ip = $request->header('X-Forwarded-For');
        if ($ip) {
            $ip = trim(explode(',', $ip)[0]);
        } else {
            $ip = $request->ip();
        }

        $fmsPayload = [
            'correlation_id' => $correlationId,
            'user_id' => $challenge->user_id,
            'identifier' => null,
            'device_id' => $challenge->device_id,
            'ip' => $ip,
            'user_agent' => $request->userAgent(),
            'success' => true,
            'mfa_verified' => true,
            'occurred_at' => now()->toIso8601String(),
        ];
        try { $fms->evaluateLoginAttempt($fmsPayload); } catch (\Throwable $e) { /* ignore */ }

        // Issue opaque token + internal JWT (same as LoginController)
        $opaque = 'opaque_' . Str::random(48);

        $secret = env('JWT_SECRET');
        if (!$secret) return response()->json(['message' => 'JWT_SECRET not set'], 500);

        $ttlSeconds = (int) env('JWT_TTL_SECONDS', 900);
        $now = time();
        $issuer = env('JWT_ISSUER', 'auth-service');
        $aud = env('JWT_AUDIENCE', 'banking-gateway');

        $payload = [
            'typ' => 'access',
            'iss' => $issuer,
            'aud' => $aud,
            'sub' => (int) $challenge->user_id,
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
            'mfa_verified' => true,
        ]);
    }
}
