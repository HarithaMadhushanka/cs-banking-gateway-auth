<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class VerifyJwt
{
    public function handle(Request $request, Closure $next): Response
    {
        $auth = $request->header('Authorization', '');

        if (!preg_match('/^Bearer\s+(.+)$/i', $auth, $m)) {
            return response()->json(['message' => 'missing token'], 401);
        }

        $token = trim($m[1]);
        $secret = env('JWT_SECRET');

        if (!$secret) {
            return response()->json(['message' => 'JWT_SECRET not set'], 500);
        }

        try {
            \Firebase\JWT\JWT::$leeway = 30; // seconds of clock skew tolerance

            // validates signature + exp/iat/nbf automatically
            $decoded = JWT::decode($token, new Key($secret, 'HS256'));

            $claims = (array) $decoded;

            $required = ['iss', 'aud', 'sub', 'iat', 'exp', 'jti'];
            foreach ($required as $k) {
                if (!array_key_exists($k, $claims)) {
                    return response()->json(['message' => 'invalid token'], 401);
                }
            }

            if (($claims['iss'] ?? null) !== config('app.url')) {
                return response()->json(['message' => 'invalid token'], 401);
            }

            if (($claims['aud'] ?? null) !== 'banking-gateway') {
                return response()->json(['message' => 'invalid token'], 401);
            }

            $request->attributes->set('jwt', $claims);
        } catch (\Throwable $e) {
            return response()->json(['message' => 'invalid token'], 401);
        }

        return $next($request);
    }
}
