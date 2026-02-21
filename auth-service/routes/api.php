<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuditTestController;
use App\Http\Controllers\LoginController;
use App\Http\Controllers\LogoutController;
use App\Http\Controllers\MfaController;
use App\Http\Controllers\AdminFmsLogsController;
use App\Http\Controllers\AdminFmsDevicesController;


Route::post('/login', [LoginController::class, 'login']);
Route::post('/logout', [LogoutController::class, 'logout']);
Route::post('/mfa/verify', [MfaController::class, 'verify']);

Route::middleware(['verify.jwt'])->group(function () {
    Route::post('/audit/test', [AuditTestController::class, 'test']);
    Route::get('/admin/fms/logs', [AdminFmsLogsController::class, 'index']);
    Route::get('/admin/fms/devices', [AdminFmsDevicesController::class, 'index']);
});