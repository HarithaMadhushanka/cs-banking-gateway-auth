<?php

namespace App\Http\Middleware;

use App\Models\AuditLog;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class AuditMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        // Resolve or generate correlation ID
        $correlationId =
            $request->header('X-Correlation-ID')
            ?? $request->header('X-Request-ID')
            ?? (string) Str::uuid();

        // Ensure request carries correlation ID
        $request->headers->set('X-Correlation-ID', $correlationId);

        // IMPORTANT: allow auth + routing to run first
        $response = $next($request);

        // Write audit entry AFTER request is processed
        AuditLog::create([
            'user_id' => optional($request->user())->id,
            'event_type' => strtoupper($request->method()) . ' ' . $request->path(),
            'ip' => $request->ip(),
            'user_agent' => substr((string) $request->userAgent(), 0, 255),
            'correlation_id' => substr($correlationId, 0, 64),
            'metadata' => [
                'query' => $request->query(),
                'status' => method_exists($response, 'getStatusCode')
                    ? $response->getStatusCode()
                    : null,
            ],
        ]);

        // Propagate correlation ID back to client
        $response->headers->set('X-Correlation-ID', $correlationId);

        return $response;
    }
}
