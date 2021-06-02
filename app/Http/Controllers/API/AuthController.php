<?php
/**
 *  app/Http/Controllers/API/AuthController.php
 *
 * Date-Time: 02.06.21
 * Time: 16:28
 * @author Vito Makhatadze <vitomaxatadze@gmail.com>
 */

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

/**
 * Class AuthController
 * @package App\Http\Controllers\API
 */
class AuthController extends Controller
{

    /**
     * @param \Illuminate\Http\Request $request
     *
     * @return \Illuminate\Contracts\Foundation\Application|\Illuminate\Contracts\Routing\ResponseFactory|\Illuminate\Http\Response
     */
    public function register(Request $request)
    {
        $data = $request->validate([
            'name' => 'required|string|max:191',
            'email' => 'required|string|max:191|unique:users,email',
            'password' => 'required|string'
        ]);

        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password'])
        ]);

        $token = $user->createToken('foundProjectToken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    public function login(Request $request)
    {
        $data = $request->validate([
            'email' => 'required|email|max:191',
            'password' => 'required|string'
        ]);

        $user = User::where('email', $data['email'])->first();

        if (!$user || !Hash::check($data['password'], $user->password)) {
            return response([
                'message' => 'Invalid Credentials',
                401
            ]);
        }
        $token = $user->createToken('foundProjectTokenLogin')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 200);
    }


    /**
     * @return \Illuminate\Contracts\Foundation\Application|\Illuminate\Contracts\Routing\ResponseFactory|\Illuminate\Http\Response
     */
    public function logout()
    {
        auth()->user()->tokens()->delete();
        return response([
            'message' => 'Logged Out Successfully.'
        ]);
    }
}
