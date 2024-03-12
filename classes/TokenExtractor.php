<?php

namespace Golem15\User\Classes;

use Illuminate\Http\Request;

class TokenExtractor
{
    public static function fromRequest(Request $request): ?string
    {
        $header = $request->header('Authorization');
        if (is_string($header) && preg_match('/^Bearer\s+(.+)$/', $header, $matches)) {
            return $matches[1];
        }
        if ($request->get('jwt_token')) {
            return $request->get('jwt_token');
        }

        return null;
    }
}
