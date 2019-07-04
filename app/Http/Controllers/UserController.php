<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use JWTAuth;

class UserController extends Controller
{
	/*
		This method attempts to log a user in and generates an authorization token if the user is found in the database.
		It throws an error if the user is not found or if an exception occurred while trying to find the user.
	*/
    public function authenticate(Request $request)
    {
    	$credentials = $request->only('email', 'password');

    	try {
    		if (!$token = JWTAuth::attempt($credentials)) {
    			return response()->json(['error' => 'invalid_credentials'], 400);
    		}
    	} catch (JWTException $e) {
    		return response()->json(['error' => 'count_not_create_token'], 500);
    	}

    	return response()->json(compact('token'));
    }

    /*
    	This method validates a user input and creates a user if the user credentials are validated. 
    	The user is then passed on to JWTAuth to generate an access token for the created user.
    	This way, the user would not need to log in to get it.
    */
    public function register(Request $request)
    {
    	$validator = Validator::make($request->all(), [
    		'name' => 'required|string|max:255',
    		'email' => 'required|string|email|max:255|unique:users',
    		'password' => 'required|string|max:6|confirmed'
    	]);

    	if ($validator->fails()) {
    		return response()->json($validator->errors()->toJson(), 400);
    	}

    	$user = User::create([
    		'name' => $request->get('name'),
    		'email' => $request->get('email'),
    		'password' => Hash::make($request->get('password'))
    	]);

    	$token = JWTAuth::fromUser($user);

    	return response()->json(compact('user', 'token'), 201);
    }

	/*
		This method which returns the user object based on the authorization token that is passed.
	*/
    public function getAuthenticatedUser()
    {
    	try {
    		if (!$user = JWTAuth::parseToken()->authenticate()) {
    			return response()->json(['user_not_found'], 404);
    		}
    	} catch (TokenExpiredException $e) {
    		return response()->json(['token_expired'], $e->getStatusCode());
    	} catch (TokenInvalidException $e) {
    		return response()->json(['token_invalid'], $e->getStatusCode());
    	} catch (JWTException $e) {
    		return response()->json(['token_absent'], $e->getStatusCode());
    	}

    	return response()->json(compact('user'));
    }
}
