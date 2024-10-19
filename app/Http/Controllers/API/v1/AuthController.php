<?php

namespace App\Http\Controllers\API\v1;

use App\Http\Controllers\Controller;
use App\Http\Requests\GoogleAuthRequest;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Str;
use App\Services\ResponseService;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Psr7\Request;
use Illuminate\Http\JsonResponse;
use Laravel\Socialite\Contracts\User as SocialiteUser;

class AuthController extends Controller
{
    protected $responseService;

    public function __construct(ResponseService $responseService)
    {
        $this->responseService = $responseService;
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
        // Create a new user
        $user = new User;
        $user->name = $request->input('name');
        $user->email = $request->input('email');
        $user->password = bcrypt($request->input('password')); // Hash the password
        $user->role = $request->input('role');
        $user->save();

        // Generate a JWT token for the newly registered user
        $token = auth()->login($user); // Assuming you're using the JWT Auth package

        return $this->responseService->success(
            trans('messages.user_registered_successfully'),
            [
                'user_id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'role' => $user->role,
                'access_token' => $token, // Include the token in the response
                'token_type' => 'Bearer', // Specify the token type
            ],
            201
        );
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(LoginRequest $request)
    {
        $credentials = $request->only(['email', 'password']);

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
    public function GoogleAuth(GoogleAuthRequest $request)
    {
        $validatedData = $request->validated();

        // Attempt to find the user by email
        $authUser = User::firstOrNew(['email' => $validatedData['email']]);

        // Store the Google ID for existing users
        if (!$authUser->exists) {
            $authUser->google_id = $validatedData['id']; // Save Google ID for new users
        }

        // Handle login or registration
        if ($authUser->exists) {
            return $this->GoogleLogin($authUser);
        } else {
            return $this->GoogleRegister($validatedData);
        }
    }

    private function GoogleLogin(User $authUser)
    {
        // Check if the user has a role
        if (!$authUser->role) {
            return $this->responseService->error(trans('messages.please_select_role'), [], 400);
        }

        // Generate the token
        $token = auth()->login($authUser);

        if (!$token) {
            return $this->responseService->error('Token generation failed', [], 500);
        }

        return $this->responseService->success(trans('messages.login_successful'), [
            'access_token' => $this->respondWithToken($token),
        ]);
    }

    private function GoogleRegister(array $validatedData)
    {
        // Create a new user
        $authUser = new User();
        $authUser->fill([
            'name' => $validatedData['name'],
            'google_id' => $validatedData['id'],
            'avatar' => $validatedData['avatar'],
            'email' => $validatedData['email'],
            'role' => $validatedData['role'],
            'email_verified_at' => now(),
            'password' => bcrypt(Str::random(16)), // Generate a random password
        ]);

        // Save the user
        $authUser->save();

        // Automatically log in the new user
        $token = auth()->login($authUser);

        if (!$token) {
            return $this->responseService->error('Token generation failed', [], 500);
        }

        return $this->responseService->success(trans('messages.registration_successful'), [
            'access_token' => $this->respondWithToken($token),
        ]);
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

        $authUser = auth()->user();

        if (!$authUser) {
            return $this->responseService->error(trans('messages.user_not_authenticated'), [], 401);
        }

        $authUser->role = request()->input('role');
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
        // Generate the token using the respondWithToken method
        $tokenData = $this->respondWithToken(auth()->refresh());

        // Use ResponseService to return the success response
        return $this->responseService->success(trans('messages.token_refreshed_successfully'), $tokenData);
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

        return $response; // Return the array instead of a JSON response
    }

    /**
     * Redirect to Google for authentication.
     *
     * @return \Illuminate\Http\RedirectResponse
     */
}
