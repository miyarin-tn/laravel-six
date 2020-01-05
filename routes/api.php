<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

/* Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
}); */

Route::post('/register', 'AuthController@register');
Route::post('/login', 'AuthController@login');
Route::get('/confirm-email/{token}', 'AuthController@confirmEmail');
Route::group(['middleware' => 'auth:api'], function() {
    Route::get('profile', 'AuthController@profile');
    Route::get('logout', 'AuthController@logout');
});
Route::group(['middleware' => 'api', 'prefix' => 'password'], function () {
    Route::post('make-reset', 'PasswordResetController@makeReset');
    Route::get('check-reset/{token}', 'PasswordResetController@checkReset');
    Route::put('apply-reset', 'PasswordResetController@applyReset');
});
Route::get('refresh-token/{token}', 'AuthController@refreshToken');
