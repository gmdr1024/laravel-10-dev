<?php

namespace App\Http\Controllers\Passport;

use App\Models\User;
use Exception;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Laravel\Passport\Bridge\User as BridgeUser;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Contracts\AuthorizationViewResponse;
use Laravel\Passport\Http\Controllers\AuthorizationController as BaseController;
use Laravel\Passport\TokenRepository;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use Nyholm\Psr7\Response as Psr7Response;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationController extends BaseController
{
    /**
     * Create a new controller instance.
     *
     * @param  \League\OAuth2\Server\AuthorizationServer  $server
     * @param  \Illuminate\Contracts\Auth\StatefulGuard  $guard
     * @param  \Laravel\Passport\Contracts\AuthorizationViewResponse  $response
     * @return void
     */
    public function __construct(AuthorizationServer $server,
                                StatefulGuard $guard,
                                AuthorizationViewResponse $response)
    {
        parent::__construct(
            $server,
            $guard,
            $response
        );
    }

    /**
     * Authorize a client to access the user's account.
     *
     * @param  \Psr\Http\Message\ServerRequestInterface  $psrRequest
     * @param  \Illuminate\Http\Request  $request
     * @param  \Laravel\Passport\ClientRepository  $clients
     * @param  \Laravel\Passport\TokenRepository  $tokens
     * @return \Illuminate\Http\Response|\Laravel\Passport\Contracts\AuthorizationViewResponse
     */
    public function authorize(ServerRequestInterface $psrRequest,
                              Request $request,
                              ClientRepository $clients,
                              TokenRepository $tokens)
    {
        $authRequest = $this->withErrorHandling(function () use ($psrRequest) {
            return $this->server->validateAuthorizationRequest($psrRequest);
        });

        // if ($this->guard->guest()) {
        //     return $request->get('prompt') === 'none'
        //             ? $this->denyRequest($authRequest)
        //             : $this->promptForLogin($request);
        // }

        // if ($request->get('prompt') === 'login' &&
        //     ! $request->session()->get('promptedForLogin', false)) {
        //     $this->guard->logout();
        //     $request->session()->invalidate();
        //     $request->session()->regenerateToken();

        //     return $this->promptForLogin($request);
        // }

        // $request->session()->forget('promptedForLogin');

        try {
            $request->validate([
                'email' => 'required|email',
                'password' => 'required',
            ]);
        } catch (ValidationException $e) {
            return response()->json($e->errors(), 422);
        }

        try {
            $user = User::where('email', $request->input('email'))->firstOrFail();
        } catch (ModelNotFoundException $e) {
            return response()->json([], 404);
        }

        Auth::login($user);

        $scopes = $this->parseScopes($authRequest);

        $client = $clients->find($authRequest->getClient()->getIdentifier());

        if ($request->get('prompt') !== 'consent' &&
            ($client->skipsAuthorization() || $this->hasValidToken($tokens, $user, $client, $scopes))) {
            return $this->approveRequest($authRequest, $user);
        }

        if ($request->get('prompt') === 'none') {
            return $this->denyRequest($authRequest, $user);
        }

        $request->session()->put('authToken', $authToken = Str::random());
        $request->session()->put('authRequest', $authRequest);

        return $this->response->withParameters([
            'client' => $client,
            'user' => $user,
            'scopes' => $scopes,
            'request' => $request,
            'authToken' => $authToken,
        ]);
    }

    /**
     * Approve the authorization request.
     *
     * @param  \League\OAuth2\Server\RequestTypes\AuthorizationRequest  $authRequest
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return \Illuminate\Http\Response
     */
    protected function approveRequest($authRequest, $user)
    {
        $authRequest->setUser(new BridgeUser($user->getAuthIdentifier()));

        $authRequest->setAuthorizationApproved(true);

        return $this->withErrorHandling(function () use ($authRequest) {
            return $this->convertResponse(
                $this->server->completeAuthorizationRequest($authRequest, new Psr7Response)
            );
        });
    }

    /**
     * Deny the authorization request.
     *
     * @param  \League\OAuth2\Server\RequestTypes\AuthorizationRequest  $authRequest
     * @param  \Illuminate\Contracts\Auth\Authenticatable|null  $user
     * @return \Illuminate\Http\Response
     */
    protected function denyRequest($authRequest, $user = null)
    {
        if (is_null($user)) {
            $uri = $authRequest->getRedirectUri()
                ?? (is_array($authRequest->getClient()->getRedirectUri())
                    ? $authRequest->getClient()->getRedirectUri()[0]
                    : $authRequest->getClient()->getRedirectUri());

            $separator = $authRequest->getGrantTypeId() === 'implicit' ? '#' : '?';

            $uri = $uri.(str_contains($uri, $separator) ? '&' : $separator).'state='.$authRequest->getState();

            return $this->withErrorHandling(function () use ($uri) {
                throw OAuthServerException::accessDenied('Unauthenticated', $uri);
            });
        }

        $authRequest->setUser(new BridgeUser($user->getAuthIdentifier()));

        $authRequest->setAuthorizationApproved(false);

        return $this->withErrorHandling(function () use ($authRequest) {
            return $this->convertResponse(
                $this->server->completeAuthorizationRequest($authRequest, new Psr7Response)
            );
        });
    }
}
