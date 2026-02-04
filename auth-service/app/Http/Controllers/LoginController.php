<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Str;
use Firebase\JWT\JWT;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'email' => ['required', 'email'],
        ]);

        // Demo-only: replace with real auth later
        $userId = 1;
        $email = $request->input('email');

        $ttlSeconds = 900; // 15 minutes
        $now = time();

        $secret = env('JWT_SECRET');
        if (!$secret) {
            return response()->json(['message' => 'JWT_SECRET not set'], 500);
        }

        // Opaque token (client-facing)
        $opaque = 'opaque_' . Str::random(48);

        $payload = [
            'typ' => 'access',                  // token type
            'iss' => config('app.url'),         // issuer
            'aud' => 'banking-gateway',         // audience
            'sub' => $userId,                   // user id
            'email' => $email,

            'iat' => $now,
            'nbf' => $now - 5,                  // tolerate small skew
            'exp' => $now + $ttlSeconds,

            'jti' => (string) Str::uuid(),      // unique token id
            'sid' => $opaque,                   // session id (bind jwt to opaque)
        ];

        $jwt = JWT::encode($payload, $secret, 'HS256');

        // Redis mapping for gateway lookup
        Redis::setex("opaque:token:{$opaque}", $ttlSeconds, $jwt);

        return response()->json([
            'access_token' => $opaque,
            'token_type' => 'Bearer',
            'expires_in' => $ttlSeconds,
        ]);
    }
}
