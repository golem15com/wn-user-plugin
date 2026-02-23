<?php
namespace Golem15\User\Middleware;

use Closure;
use PHPOpenSourceSaver\JWTAuth\Http\Middleware\Authenticate;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

class JwtAuthenticate extends Authenticate
{
    public function handle($request, Closure $next)
    {
        try {
            $this->authenticate($request);
        } catch (UnauthorizedHttpException $e) {
            // Auth-related errors (token missing, expired, invalid, user not found)
            return response()->json(['error' => true, 'message' => $e->getMessage()], $e->getStatusCode());
        } catch (\Exception $e) {
            // Unexpected errors (database, config, etc.)
            \Log::error('JWT Auth unexpected error: ' . $e->getMessage(), ['exception' => $e]);
            return response()->json(['error' => true, 'message' => 'Authentication error'], 500);
        }

        // Set the default guard to 'api' so auth()->id() resolves the JWT user
        auth()->shouldUse('api');

        return $next($request);
    }
}
