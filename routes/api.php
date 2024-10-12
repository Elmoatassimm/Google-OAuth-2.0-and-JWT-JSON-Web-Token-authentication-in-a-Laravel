<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\v1\AuthController;

Route::group([
    'middleware' => ['api', 'auth:api'], // Apply 'auth:api' to the entire group
    'prefix' => 'auth'
], function ($router) {
    Route::post('/register', [AuthController::class, 'register'])->withoutMiddleware('auth:api')->name('register');
    Route::post('/login', [AuthController::class, 'login'])->withoutMiddleware('auth:api')->name('login');

    Route::post('/logout', [AuthController::class, 'logout'])->name('logout');
    Route::post('/refresh', [AuthController::class, 'refresh'])->name('refresh');
    Route::post('/me', [AuthController::class, 'me'])->name('me');



    Route::post('/assign-role', [AuthController::class, 'assignRoleToAuthUser'])->name('assign-role');
});
Route::post('/auth/google-auth', [AuthController::class, 'GoogleAuth']);
