<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Str;
use Firebase\JWT\JWT;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required', 'string', 'min:6'],
        ]);

        $email = $request->input('email');
        $password = $request->input('password');

        $user = User::where('email', $email)->first();

        if (!$user || !Hash::check($password, $user->password)) {
            return response()->json(['message' => 'invalid credentials'], 401);
        }

        $userId = (int) $user->id;

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
            'sid' => $opaque, // bind to opaque session
        ];


        $jwt = JWT::encode($payload, $secret, 'HS256');

        // Redis mapping for gateway lookup
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
