<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use App\Models\AuditLog;
use Illuminate\Support\Facades\DB;

class AuditMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        // Determine correlation ID
        $correlationId =
            $request->header('X-Correlation-ID')
            ?? $request->header('X-Request-ID')
            ?? (string) Str::uuid();

        // Write audit log
        DB::table('audit_logs')->insert([
            'user_id' => optional($request->user())->id,
            'event_type' => $request->method().' '.$request->path(),
            'ip' => $request->ip(),
            'user_agent' => substr((string) $request->userAgent(), 0, 255),
            'correlation_id' => substr($correlationId, 0, 64),
            'metadata' => json_encode([
                'query' => $request->query(),
            ]),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // Let request continue
        $response = $next($request);

        // Attach correlation ID to response
        $response->headers->set('X-Correlation-ID', $correlationId);

        return $response;
    }
}
