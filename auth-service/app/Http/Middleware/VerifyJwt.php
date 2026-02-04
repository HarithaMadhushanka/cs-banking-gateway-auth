<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use App\Models\User;

class VerifyJwt
{
    public function handle(Request $request, Closure $next): Response
    {
        $auth = $request->header('Authorization', '');

        if (!preg_match('/^Bearer\s+(.+)$/i', $auth, $m)) {
            return response()->json(['message' => 'missing token'], 401);
        }

        $token = trim($m[1]);
        if ($token === '') {
            return response()->json(['message' => 'missing token'], 401);
        }

        $secret = env('JWT_SECRET');
        if (!$secret) {
            return response()->json(['message' => 'JWT_SECRET not set'], 500);
        }

        try {
            // Allow clock skew (seconds) when validating exp/nbf/iat
            JWT::$leeway = (int) env('JWT_LEEWAY_SECONDS', 10);

            // Validates signature + exp/iat/nbf automatically
            $decoded = JWT::decode($token, new Key($secret, 'HS256'));
            $claims = (array) $decoded;

            // Required claims
            $required = ['typ','iss','aud','sub','iat','nbf','exp','jti','sid'];
            foreach ($required as $k) {
                if (!array_key_exists($k, $claims)) {
                    return response()->json(['message' => 'invalid token'], 401);
                }
            }

            // Type
            if (($claims['typ'] ?? null) !== 'access') {
                return response()->json(['message' => 'invalid token'], 401);
            }

            // Issuer & audience
            if (($claims['iss'] ?? null) !== env('JWT_ISSUER', 'auth-service')) {
                return response()->json(['message' => 'invalid token'], 401);
            }
            if (($claims['aud'] ?? null) !== env('JWT_AUDIENCE', 'banking-gateway')) {
                return response()->json(['message' => 'invalid token'], 401);
            }

            // Subject sanity (user id)
            if (!is_int($claims['sub']) && !(is_string($claims['sub']) && ctype_digit($claims['sub']))) {
                return response()->json(['message' => 'invalid token'], 401);
            }

            $userId = (int) $claims['sub'];
            $user = User::find($userId);
            if (!$user) {
                return response()->json(['message' => 'invalid token'], 401);
            }

            if (!is_string($claims['sid'] ?? null) || !str_starts_with($claims['sid'], 'opaque_')) {
                return response()->json(['message' => 'invalid token'], 401);
            }

            $opaqueHeader = $request->header('X-Opaque-Token');
            if (!$opaqueHeader || $opaqueHeader !== $claims['sid']) {
                return response()->json(['message' => 'invalid token'], 401);
            }

            // Time claim sanity (must be ints)
            foreach (['iat', 'nbf', 'exp'] as $t) {
                if (!is_int($claims[$t]) && !(is_string($claims[$t]) && ctype_digit($claims[$t]))) {
                    return response()->json(['message' => 'invalid token'], 401);
                }
                $claims[$t] = (int) $claims[$t];
            }

            // Extra hardening: reject tokens with iat too far in the future
            // (still allows JWT::$leeway slack)
            $now = time();
            if ($claims['iat'] > ($now + 60)) { // > 60s in future
                return response()->json(['message' => 'invalid token'], 401);
            }

            // Attach claims for controllers
            $request->attributes->set('jwt', $claims);
            $request->setUserResolver(fn () => $user);
        } catch (\Throwable $e) {
            return response()->json(['message' => 'invalid token'], 401);
        }

        return $next($request);
    }
}
