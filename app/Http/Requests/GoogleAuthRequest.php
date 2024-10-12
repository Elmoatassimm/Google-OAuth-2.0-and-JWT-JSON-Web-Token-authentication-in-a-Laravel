<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

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
        ];
    }
}
