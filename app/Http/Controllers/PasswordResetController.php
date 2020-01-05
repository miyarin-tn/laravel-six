<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Carbon\Carbon;
use App\Notifications\PasswordResetRequest;
use App\Notifications\PasswordResetSuccess;
use App\User;
use App\PasswordReset;

class PasswordResetController extends Controller
{
    /**
     * Create token password reset
     *
     * @param  [string] email
     * @return [string] message
     */
    public function makeReset(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
        ]);
        $user = User::where('email', $request->email)->first();
        if (!$user)
            return response()->json([
                'message' => 'We can\'t find a account with this e-mail address.'
            ], 404);
        $infoReset = PasswordReset::updateOrCreate(
            ['email' => $user->email],
            [
                'email' => $user->email,
                'token' => Str::random(60)
            ]
        );
        // if ($user && $infoReset)
            // $user->notify(new PasswordResetRequest($infoReset->token));
        return response()->json([
            'message' => 'We have e-mailed your password reset link!'
        ]);
    }

    /**
     * Find token password reset
     *
     * @param  [string] $token
     * @return [string] message
     * @return [json] passwordReset object
     */
    public function checkReset($token)
    {
        $tokenReset = PasswordReset::where('token', $token)->first();
        if (!$tokenReset)
            return response()->json([
                'message' => 'This password reset token is invalid.'
            ], 401);
        if (Carbon::parse($tokenReset->updated_at)->addMinutes(720)->isPast()) {
            $tokenReset->delete();
            return response()->json([
                'message' => 'This password reset token has expired.'
            ], 401);
        }
        return response()->json($tokenReset);
    }

    /**
     * Reset password
     *
     * @param  [string] email
     * @param  [string] password
     * @param  [string] password_confirmation
     * @param  [string] token
     * @return [string] message
     * @return [json] user object
     */
    public function applyReset(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string|confirmed',
            'token' => 'required|string'
        ]);
        $infoReset = PasswordReset::where([
            ['email', $request->email],
            ['token', $request->token]
        ])->first();
        if (!$infoReset)
            return response()->json([
                'message' => 'This password reset token is invalid.'
            ], 401);
        $user = User::where('email', $infoReset->email)->first();
        if (!$user)
            return response()->json([
                'message' => 'We can\'t find a account with this e-mail address.'
            ], 404);
        $user->password = bcrypt($request->password);
        $user->save();
        $infoReset->delete();
        return response()->json($user);
    }
}
