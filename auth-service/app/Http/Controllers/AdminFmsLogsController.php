<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class AdminFmsLogsController extends Controller
{
    public function index(Request $request)
    {
        // 1) Admin check
        // If you already attach the authenticated user to the request, use that:
        $user = $request->user(); // common Laravel pattern
        if (!$user || ($user->role ?? 'user') !== 'admin') {
            return response()->json(['message' => 'forbidden'], 403);
        }

        // 2) Proxy request to FMS internal endpoint
        // We will call an INTERNAL FMS endpoint inside docker network.
        // Keep query params for pagination.
        $page = (int) $request->query('page', 1);
        $perPage = (int) $request->query('per_page', 25);

        $base = rtrim(env('FMS_BASE_URL', 'http://fms-service:9100'), '/');
        $url = $base . '/api/internal/admin/logs';

        $resp = Http::timeout(6)
            ->withHeaders([
                'X-Internal-Key' => env('INTERNAL_SERVICE_KEY'),
                'Accept' => 'application/json',
            ])
            ->get($url, [
                'page' => $page,
                'per_page' => $perPage,
            ]);

        $data = $resp->json();

        if (!is_array($data)) {
            return response($resp->body(), $resp->status())
                ->header('Content-Type', $resp->header('Content-Type', 'application/json'));
        }

        // Build the PUBLIC URL the mobile/web app uses (through Kong)
        $publicBase = rtrim(env('PUBLIC_BASE_URL', 'http://localhost:8000'), '/');
        $publicPath = $publicBase . '/api/auth/admin/fms/logs';

        $data['path'] = $publicPath;
        $data['first_page_url'] = $publicPath . '?page=1';
        $data['last_page_url'] = $publicPath . '?page=' . ((int)($data['last_page'] ?? 1));
        $data['next_page_url'] = isset($data['next_page_url']) && $data['next_page_url']
            ? $publicPath . '?page=' . (((int)($data['current_page'] ?? 1)) + 1)
            : null;
        $data['prev_page_url'] = isset($data['prev_page_url']) && $data['prev_page_url']
            ? $publicPath . '?page=' . (((int)($data['current_page'] ?? 1)) - 1)
            : null;

        // Fix the paginator "links" array
        if (isset($data['links']) && is_array($data['links'])) {
            foreach ($data['links'] as &$l) {
                if (!isset($l['label'])) continue;

                $label = strip_tags((string)$l['label']);

                if (is_numeric($label)) {
                    $l['url'] = $publicPath . '?page=' . ((int)$label);
                } elseif (str_contains($label, 'Next')) {
                    $l['url'] = $data['next_page_url'];
                } elseif (str_contains($label, 'Previous')) {
                    $l['url'] = $data['prev_page_url'];
                }
            }
        }

        return response()->json($data, $resp->status());
    }
}