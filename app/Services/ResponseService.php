<?php

namespace App\Services;

use Illuminate\Http\JsonResponse;

class ResponseService
{
    /**
     * Return a success JSON response.
     *
     * @param string $message
     * @param array $data
     * @param int $status
     * @return JsonResponse
     */
    public function success(string $message = 'Operation Successful', array $data = [], int $status = 200): JsonResponse
    {
        return response()->json([
            'status' => 'success',
            'message' => __($message),
            'data' => $data,
        ], $status);
    }

    /**
     * Return an error JSON response.
     *
     * @param string $message
     * @param array $errors
     * @param int $status
     * @return JsonResponse
     */
    public function error(string $message = '', array $errors = [], int $status = 400): JsonResponse
{
    return response()->json([
        'message' => $message,
        'errors' => $errors,
    ], $status);
}


    /**
     * Return a not found response.
     *
     * @param string $message
     * @return JsonResponse
     */
    public function notFound(string $message = 'Resource Not Found'): JsonResponse
    {
        return $this->error(__($message), [], 404);
    }

    /**
     * Return a validation failure response.
     *
     * @param array $errors
     * @param string $message
     * @return JsonResponse
     */
    public function validationFailed(array $errors, string $message = 'Validation Failed'): JsonResponse
    {
        return $this->error(__($message), $errors, 422);
    }
}
