<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    public function list()
    {
        $users = DB::table('users')->select('id', 'username')->get();
        return response()->json($users, 200);
    }

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required',
            'password' => 'required'
        ]);
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $user = DB::table('users')->where('username', $request->username)->first();
        if ($user) {
            return response()->json(["message" => "This username already exist!"], 400);
        }

        $user_id = DB::table('users')->insertGetId([
            'username' => $request->username,
            'password' => bcrypt($request->password)
        ]);


        $token = hash('sha256', $request->username . $request->password);
        DB::table('personal_access_tokens')->insert([
            'user_id' => $user_id,
            'token' => $token,
            'created_at' => Carbon::now(),
            'updated_at' => Carbon::now(),
        ]);

        return response()->json([
            'message' => 'User registered successfully.',
            'token' => $token
        ], 201);
    }

    public function check_auth(Request $request)
    {
        $username = $request->header('username');
        $token = $request->header('token');
        if ($username == '' || $token == '') {
            return response()->json(['message' => 'Please send username and token.'], 400);
        }

        $user = DB::table('users')->where('username', $username)->first();

        if (!$user) {
            return response()->json(["message" => "This username does not exist!"], 400);
        }

        $data = DB::table('personal_access_tokens')
            ->where('user_id', $user->id)
            ->where('token', $token)
            ->first();

        if ($data) {

            return response()->json([
                "message" => "Token is valid",
                "isvalid" => 1
            ], 200);

        } else {

            return response()->json([
                "message" => "Token is invalid",
                "isvalid" => 0
            ], 400);

        }
    }

    public function panel(Request $request)
    {
        $username = $request->header('username');
        $token = $request->header('token');
        if (is_null($username) || is_null($token)) {
            return response()->json(['message' => 'Please send username and token.'], 400);
        }

        $user = DB::table('users')->where('username', $username)->first();
        if (!$user) {
            return response()->json(["message" => "This username does not exist!"], 400);
        }

        $token = DB::table('personal_access_tokens')
            ->where('user_id', $user->id)
            ->where('token', $token)
            ->first();

        if ($token) {

            $data = DB::table('reserves')->where('user_id', $username)
                ->join('users', 'users.id', '=', 'reserves.user_id')
                ->select('reserves.id', 'reserves.user_id', 'reserves.flight_id')
                ->get();
            return response()->json([
                $data
            ], 200);

        } else {

            return response()->json([
                "message" => "Token is invalid", "isvalid" => 0
            ], 400);

        }
    }

    public function refresh(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required',
            'password' => 'required'
        ]);
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $user = DB::table('users')->where('username', $request->username)->first();
        if (!$user) {
            return response()->json(["message" => "This username does not exist!"], 400);
        }

        if (Hash::check($request->password, $user->password)) {
            $token = hash('sha256', $request->username . $request->password);

            DB::table('personal_access_tokens')->where('user_id',$user->id)->update([
                'token' => $token,
                'updated_at' => Carbon::now(),
            ]);

            return response()->json([
                'message' => 'Token refreshed successfully.',
                'token' => $token
            ], 200);

        } else {

            return response()->json([
                'message' => 'Username or password is wrong!',
            ], 401);

        }
    }
}
