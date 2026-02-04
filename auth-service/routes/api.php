<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuditTestController;
use App\Http\Controllers\LoginController;
use App\Http\Controllers\LogoutController;


Route::post('/login', [LoginController::class, 'login']);
Route::post('/logout', [LogoutController::class, 'logout']);

Route::middleware(['verify.jwt'])->group(function () {
    Route::post('/audit/test', [AuditTestController::class, 'test']);
});