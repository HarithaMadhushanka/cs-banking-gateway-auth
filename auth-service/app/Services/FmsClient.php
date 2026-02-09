<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;

class FmsClient
{
    public function evaluateLoginAttempt(array $payload): array
    {
        $baseUrl = config('services.fms.base_url');

        $res = Http::timeout(3)->acceptJson()->post(
            rtrim($baseUrl, '/') . '/api/v1/events/login-attempt',
            $payload
        );

        return [
            'ok' => $res->ok(),
            'status' => $res->status(),
            'json' => $res->json(),
        ];
    }
}
