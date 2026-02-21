<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class AdminFmsDevicesController extends Controller
{
    public function index(Request $request)
    {
        $jwt = (array) ($request->attributes->get('jwt') ?? []);
        $role = strtolower((string) ($jwt['role'] ?? ''));
        $sub  = (int) ($jwt['sub'] ?? 0);

        if ($role !== 'admin' || $sub !== 2) {
            return response()->json(['message' => 'forbidden'], 403);
        }

        $page = max(1, (int) $request->query('page', 1));
        $perPage = max(1, min((int) $request->query('per_page', 10), 50));

        $params = [
            'page' => $page,
            'per_page' => $perPage,
        ];

        if ($request->filled('user_id')) $params['user_id'] = $request->query('user_id');
        if ($request->filled('device_id')) $params['device_id'] = $request->query('device_id');

        $url = rtrim(env('FMS_BASE_URL'), '/') . '/api/internal/admin/devices';

        $resp = Http::timeout(6)
            ->withHeaders([
                'X-Internal-Key' => env('INTERNAL_SERVICE_KEY'),
                'Accept' => 'application/json',
            ])
            ->get($url, $params);

        $data = $resp->json();

        if (!is_array($data)) {
            return response($resp->body(), $resp->status())
                ->header('Content-Type', $resp->header('Content-Type', 'application/json'));
        }

        $publicBase = rtrim(env('PUBLIC_BASE_URL', 'http://localhost:8000'), '/');
        $publicPath = $publicBase . '/api/auth/admin/fms/devices';

        $data['path'] = $publicPath;
        $data['first_page_url'] = $publicPath . '?page=1';
        $data['last_page_url'] = $publicPath . '?page=' . ((int)($data['last_page'] ?? 1));
        $data['next_page_url'] = isset($data['next_page_url']) && $data['next_page_url']
            ? $publicPath . '?page=' . (((int)($data['current_page'] ?? 1)) + 1)
            : null;
        $data['prev_page_url'] = isset($data['prev_page_url']) && $data['prev_page_url']
            ? $publicPath . '?page=' . (((int)($data['current_page'] ?? 1)) - 1)
            : null;

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