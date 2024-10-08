<?php
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\v1\AuthController; 

Route::get('/', function () {
    return view('welcome');
});

Route::get('/auth/google/redirect', [AuthController::class, 'redirectToGoogle']);
Route::get('/auth/google/callback', [AuthController::class, 'handleGoogleCallback']);
