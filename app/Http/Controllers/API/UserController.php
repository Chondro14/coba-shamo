<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Rules\Password;
use Throwable;

class UserController extends Controller
{
    public function register(Request $request){
        try{
            $request->validate([
                'name' => ['required','string','max:255'],
                'username' => ['required','string','max:255','min:7','unique:users'],
                'email' => ['required','email','string','max:255','unique:users'],
                'phone' => ['nullable','string','max:30'],
                'password' => ['required','string', new Password]
            ]);

            User::create([
                'name' => $request->name,
                'username' => $request->username,
                'email' => $request->email,
                'phone' => $request->phone,
                'password' => Hash::make($request->password)
            ]);

            $user = User::where('email',$request->email)->first();

            $tokenresult = $user->createToken('authToken')->plainTextToken;
            

            return ResponseFormatter::success([
                'access_token' => $tokenresult,
                'token_type' => 'Bearer',
                'user' => $user
            ],'User Registered');
        }
        catch(Exception $error){
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ],'Authentication Failed',500);
        }
        
    }

    public function login(Request $request){
        try{
            $request->validate([
                'email' => 'email|required',
                'password' => 'required'
            ]);

            $credentials = request(['email','password']);
            if(!Auth::attempt($credentials)){
                return ResponseFormatter::error([
                    'message' => 'Unauthorized'
                ],'Authentication Failed',500);
            }

            $user = User::where('email',$request->email)->first();

            if(!Hash::check($request->password, $user->password,[])){
                throw new \Exception('Invalid Credentals');
            }

            $tokenresult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $tokenresult,
                'token_type' => 'Bearer',
                'user' => $user
            ],'Authenticatd');

        }
        catch(Exception $error){
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $error
            ],'Authentication Failed',500);
        }
    }

    public function fetch(Request $request){
        return ResponseFormatter::success($request->user(),'Get Data Profile');
    }

    public function updateProfile(Request $request){

        $data = $request->all();

        $user = Auth::user();
        $user->update($data);

        return ResponseFormatter::success($user,'Profile updated');
    }
    public function logout(Request $request){

        $token = $request->user()->currentAccessToken()->delete();
        return ResponseFormatter::success($token,'Token Revoked');
    }
}
