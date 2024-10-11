<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class LoginRequest extends FormRequest
{
    // Authorize the request
    public function authorize()
    {
        return true; // Allow all users to make this request
    }

    // Define validation rules
    public function rules()
    {
        return [
            'email' => 'required|email',
            'password' => 'required|string|min:8',
        ];
    }

    public function messages()
    {
        return [
            'email.required' => __('validation.required', ['attribute' => 'email']),
            'password.required' => __('validation.required', ['attribute' => 'password']),
        ];
    }
}
