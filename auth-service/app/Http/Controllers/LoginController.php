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
        // Minimal demo input (replace with real user auth later)
        $request->validate([
            'email' => ['required', 'email'],
        ]);

        // For now: pretend the user is authenticated
        $userId = 1;
        $email = $request->input('email');
        $ttlSeconds = 900; // 15 min session
        $now = time();

        $payload = [
            'iss' => config('app.url'),          // issuer
            'aud' => 'banking-gateway',          // audience (pick a fixed string)
            'sub' => $userId,                    // subject (user id)
            'email' => $email,

            'iat' => $now,
            'nbf' => $now - 5,                   // allow small clock skew (5s)
            'exp' => $now + $ttlSeconds,

            'jti' => (string) Str::uuid(),       // unique token id
        ];

        $secret = env('JWT_SECRET');
        if (!$secret) {
            return response()->json(['message' => 'JWT_SECRET not set'], 500);
        }

        $jwt = JWT::encode($payload, $secret, 'HS256');

        $opaque = 'opaque_' . Str::random(48);

        // Gateway will lookup this
        Redis::setex("opaque:token:{$opaque}", $ttlSeconds, $jwt);

        return response()->json([
            'access_token' => $opaque,
            'token_type' => 'Bearer',
            'expires_in' => $ttlSeconds,
        ]);
    }
}
