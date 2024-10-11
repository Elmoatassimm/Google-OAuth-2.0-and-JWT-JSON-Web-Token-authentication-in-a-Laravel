<?php

namespace App\Http\Controllers\API\v1;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Str;
use App\Services\ResponseService;
use Illuminate\Support\Facades\App;

class AuthController extends Controller
{
    protected $responseService;

    // Injecting ResponseService through the constructor
    public function __construct(ResponseService $responseService)
    {
        $this->responseService = $responseService;
        // Set the locale based on the request, default to 'en'
        $locale = request()->get('lang', 'en');
        App::setLocale($locale);
    }

    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(RegisterRequest $request)
    {
        $user = new User;
        $user->name = request()->name;
        $user->email = request()->email;
        $user->password = bcrypt(request()->password);
        $user->role = request()->role;
        $user->save();

        return $this->responseService->success(trans('messages.user_registered_successfully'), [
            'user_id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
            'role' => $user->role,
        ], 201);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(LoginRequest $request)
    {
        $credentials = request()->only(['email', 'password']);

        if (!$token = auth()->attempt($credentials)) {
            return $this->responseService->error(trans('messages.invalid_credentials'), [], 401);
        }

        return $this->respondWithToken($token, trans('messages.login_successful'));
    }

    /**
     * Handle Google OAuth callback.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function handleGoogleCallback()
    {
        $googleUser = Socialite::driver('google')->user();

        // Find or create the user
        $authUser = User::firstOrCreate(
            ['email' => $googleUser->email],
            [
                'name' => $googleUser->name,
                'google_id' => $googleUser->id,
                'avatar' => $googleUser->avatar,
                'email_verified_at' => now(),
                'password' => bcrypt(Str::random(16)),
            ]
        );

        // Generate a token for the user
        $token = auth()->login($authUser);

        // Check if the user has a role
        if (!$authUser->role) {
            return $this->responseService->error(trans('messages.please_select_role'), [], 400);
        }

        // If the user has a role, respond with the token only
        return $this->respondWithToken($token, trans('messages.login_successful'));
    }

    /**
     * Assign or Update Role for the Authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function assignRoleToAuthUser()
    {
        $validator = Validator::make(request()->all(), [
            'role' => 'required|in:admin,project_manager,team_member'
        ]);

        if ($validator->fails()) {
            return $this->responseService->validationFailed($validator->errors()->toArray());
        }

        // Retrieve the authenticated user
        $authUser = auth()->user();

        if (!$authUser) {
            return $this->responseService->error(trans('messages.user_not_authenticated'), [], 401);
        }

        // Assign or update the role
        $authUser->role = request()->role;
        $authUser->save();

        return $this->responseService->success(trans('messages.role_assigned_successfully'), [
            'user_id' => $authUser->id,
            'name' => $authUser->name,
            'role' => $authUser->role,
        ]);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return $this->responseService->success(trans('messages.user_retrieved_successfully'), [
            'user' => auth()->user()
        ]);
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();
        return $this->responseService->success(trans('messages.logged_out_successfully'));
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh(), trans('messages.token_refreshed_successfully'));
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     * @param  string|null $message
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token, $message = null)
    {
        $response = [
            'success' => true,
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ];

        if ($message) {
            $response['message'] = $message;
        }

        return response()->json($response);
    }

    /**
     * Redirect to Google for authentication.
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function redirectToGoogle()
    {
        return Socialite::driver('google')->redirect();
    }
}
