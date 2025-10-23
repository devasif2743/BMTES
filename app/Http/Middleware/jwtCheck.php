<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\JWTException;

class jwtCheck
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {

         try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (TokenExpiredException $e) {
            return response()->json([
                 'status'=>false,   
                 'message' => 'Token is expired'], 200);
        } catch (TokenInvalidException $e) {
            return response()->json([
                'status'=>false, 
                'message' => 'Token is invalid'], 200);
        } catch (JWTException $e) {
            return response()->json([
                'status'=>false,     
                'message' => 'Token is not provided'], 200);
        }

        return $next($request);
    }
}
