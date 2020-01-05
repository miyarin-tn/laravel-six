<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Carbon\Carbon;
use GuzzleHttp\Client;
use DB;
use App\User;
use App\Notifications\ConfirmEmail;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->client = DB::table('oauth_clients')->where('id', 2)->first();
    }
    /**
     * Create user
     *
     * @param  [string] name
     * @param  [string] email
     * @param  [string] password
     * @param  [string] password_confirmation
     * @return [string] message
     */
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed'
        ]);
        $user = new User([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
            'activation_token' => Str::random(60)
        ]);
        $user->save();
        // $user->notify(new ConfirmEmail($user));
        return response()->json([
            'message' => 'Successfully created user!'
        ], 201);
    }
  
    /**
     * Login user
     *
     * @param  [string] email
     * @param  [string] password
     * @param  [boolean] remember_me
     * @return [string] access_token
     * @return [string] refresh_token
     * @return [string] token_type
     * @return [string] expires_in
     */
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ]);
        $credentials = request(['email', 'password']);
        $credentials['active'] = 1;
        $credentials['deleted_at'] = null;
        if(!Auth::attempt($credentials))
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);

        $http = new Client([
            'base_uri' => 'http://' . $_SERVER['HTTP_HOST'],
            'timeout' => 2.0
        ]);
        $response = $http->post('/oauth/token', [
            'form_params' => [
                'grant_type' => 'password',
                'client_id' => $this->client->id,
                'client_secret' => $this->client->secret,
                'username' => $request->email,
                'password' => $request->password,
                'scope' => ''
            ],
        ]);
        if ($response->getStatusCode() === 200) {
            return json_decode((string) $response->getBody(), true);
        } else {
            return response()->json([
                'message' => json_decode((string) $response->getBody(), true)['message']
            ], $response->getStatusCode());
        }
    }
  
    /**
     * Refresh token
     *
     * @param  [string] refresh_token
     * @return [string] access_token
     * @return [string] refresh_token
     * @return [string] token_type
     * @return [string] expires_at
     */
    public function refreshToken($token)
    {
        $http = new Client([
            'base_uri' => 'http://' . $_SERVER['HTTP_HOST'],
            'timeout' => 2.0,
            'http_errors' => false
        ]);
        $response = $http->post('/oauth/token', [
            'form_params' => [
                'grant_type' => 'refresh_token',
                'refresh_token' => $token,
                'client_id' => $this->client->id,
                'client_secret' => $this->client->secret,
                'scope' => ''
            ],
        ]);
        if ($response->getStatusCode() === 200) {
            return json_decode((string) $response->getBody(), true);
        } else {
            return response()->json([
                'message' => json_decode((string) $response->getBody(), true)['message']
            ], $response->getStatusCode());
        }
    }
  
    /**
     * Get the authenticated User
     *
     * @return [json] user object
     */
    public function profile(Request $request)
    {
        return response()->json($request->user());
    }
  
    /**
     *
     *
     * @return [string] message
     */
    public function confirmEmail($token)
    {
        $user = User::where('activation_token', $token)->first();
        if (!$user) {
            return response()->json([
                'message' => 'This activation token is invalid.'
            ], 401);
        }
        $user->active = true;
        $user->activation_token = '';
        $user->email_verified_at = Carbon::now()->timestamp;
        $user->save();
        return $user;
    }
  
    /**
     * Logout user (Revoke the token)
     *
     * @return [string] message
     */
    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    }
}
