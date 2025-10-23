<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\PunchinController;
use Illuminate\Support\Facades\Mail;
// Route::get('/user', function (Request $request) {
//     return $request->user();
// })->middleware('auth:sanctum');

Route::group(['middleware' => 'api'], function ($routes) {
    Route::post('/orginazation-login', [AuthController::class, 'login']);
    Route::post('/orginazation-register', [AuthController::class, 'register']);
    Route::post('/forget-password', [AuthController::class, 'sendOtp']);
    Route::post('/verify-otp', [AuthController::class, 'verifyOtp']);
});

Route::group(['middleware' => ['tokencheck.api'],  'prefix' => 'admin'], function ($routes) {
    // Route::post('/punch-in',[PunchinController::class,'store']);
    // Route::get('/check-punch-in',[PunchinController::class,'checkPunchIn']);



});


Route::get('/debug-send-welcome', function () {
    $email = 'sk.asif0490@gmail.com';

    try {
        Mail::to($email)->send(new App\Mail\WelcomeMail('Debug User'));
        return 'WelcomeMail send() returned OK';
    } catch (\Throwable $e) {
        \Log::error('Debug WelcomeMail send failed', ['error' => $e->getMessage(), 'trace' => $e->getTraceAsString()]);
        return 'Error: ' . $e->getMessage();
    }
});
