<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuditTestController;
use App\Http\Controllers\LoginController;


Route::get('/health', function () {
    return response()->json([
        'ok' => true,
        'service' => 'laravel-auth-api'
    ]);
});
Route::post('/audit/test', [AuditTestController::class, 'test'])->middleware('jwt');
Route::post('/login', [LoginController::class, 'login']);