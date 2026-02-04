<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;

class LogoutController extends Controller
{
    public function logout(Request $request)
    {
        // Prefer X-Opaque-Token injected by Kong plugin
        $opaque = $request->header('X-Opaque-Token');

        // Fallback: if someone calls logout directly with Authorization: Bearer opaque_...
        if (!$opaque) {
            $auth = $request->header('Authorization', '');
            if (preg_match('/^Bearer\s+(.+)$/i', $auth, $m)) {
                $opaque = trim($m[1]);
            }
        }

        if (!$opaque) {
            return response()->json(['message' => 'missing token'], 401);
        }

        // Delete the opaque -> jwt mapping
        $deleted = Redis::del("opaque:token:{$opaque}");

        return response()->json([
            'ok' => true,
            'revoked' => ($deleted === 1),
        ]);
    }
}
