<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function register(Request $request)
    {

        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:2',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json(['token' => $token, 'user' => $user], 201);
    }

    public function user(Request $request)
    {
        return $request->user();
    }
    public function login(Request $request)
    {

        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json(['message' => 'Invalid login details'], 401);
        }
        $request->user()->tokens()->delete();

        $user = Auth::user();
        $accessToken = $user->createToken('auth_token', ['access'], now()->addMinutes(1))->plainTextToken;
        $refreshToken = $user->createToken('refresh_token', ['refresh'])->plainTextToken;
        return response()->json([
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'user' => $user,
        ], 200);
    }

    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();

        return response()->json(['message' => 'Successfully logged out']);
    }

    public function refresh(Request $request)
    {
        $user = $request->user();

        // Xoá token cũ
        $request->user()->tokens()->delete();

        // Tạo token mới
        $accessToken = $user->createToken('auth_token', ['access'], now()->addMinutes(1))->plainTextToken;
        $refreshToken = $user->createToken('refresh_token', ['refresh'])->plainTextToken;

        return response()->json([
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'user' => $user,
        ], 200);
    }
}