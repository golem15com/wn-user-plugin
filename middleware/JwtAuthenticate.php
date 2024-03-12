<?php
namespace Golem15\User\Middleware;

use Closure;
use PHPOpenSourceSaver\JWTAuth\Http\Middleware\Authenticate;

class JwtAuthenticate extends Authenticate
{
    public function handle($request, Closure $next)
    {
        try {
            $this->authenticate($request);
        } catch(\Exception $e){
            return response()->json(['error' => true, 'message' => $e->getMessage()]);
        }

        return $next($request);
    }
}
