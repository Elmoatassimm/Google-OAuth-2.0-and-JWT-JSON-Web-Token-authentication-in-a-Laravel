<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use GuzzleHttp\Client;
use Illuminate\Support\Facades\Log;

class GoogleAuthRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'email' => 'required|email',
            'name' => 'required|string',
            'id' => 'required|string', // Google ID
            'avatar' => 'nullable|string',
            'role' => 'in:admin,project_manager,team_member', // Role is now required
            'token' => 'required|string', // Google token for verification
        ];
    }

    public function messages(): array
    {
        return [
            'email.required' => trans('messages.email_required'), // Customize error messages
            'email.email' => trans('messages.email_invalid'),
            'name.required' => trans('messages.name_required'),
            'id.required' => trans('messages.google_id_required'),
            'role.required' => trans('messages.role_required'),
            'role.in' => trans('messages.role_invalid'),
            'token.required' => trans('messages.token_required'),
        ];
    }

    protected function passedValidation()
    {
        $token = $this->input('token');
        $googleClientId = config('services.google.client_id'); // Ensure this is set in your services configuration

        // Verify the token using Google's token info endpoint
        $client = new Client();
        $response = $client->get('https://oauth2.googleapis.com/tokeninfo', [
            'query' => ['id_token' => $token]
        ]);

        $tokenInfo = json_decode($response->getBody(), true);

        // Ensure the token is valid and matches your Google Client ID
        if (!isset($tokenInfo['aud']) || $tokenInfo['aud'] !== $googleClientId) {
            Log::warning('Google token validation failed', ['token_info' => $tokenInfo]);
            abort(401, __('Invalid Google token.'));
        }

        // Validate the email to ensure it matches the token's email
        if ($tokenInfo['email'] !== $this->input('email')) {
            Log::warning('Google token email mismatch', ['token_email' => $tokenInfo['email'], 'input_email' => $this->input('email')]);
            abort(401, __('Token email mismatch.'));
        }
    }
}
