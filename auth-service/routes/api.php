<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuditTestController;


Route::get('/health', function () {
    return response()->json([
        'ok' => true,
        'service' => 'laravel-auth-api'
    ]);
});
Route::post('/audit/test', [AuditTestController::class, 'test']);
