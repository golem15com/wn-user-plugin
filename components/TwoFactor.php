<?php

namespace Golem15\User\Components;

use Auth;
use Event;
use Flash;
use Input;
use Lang;
use Log;
use Redirect;
use Request;
use Validator;
use ValidationException;
use ApplicationException;
use Cms\Classes\ComponentBase;
use Cms\Classes\Page;
use Golem15\User\Classes\TwoFactor\TwoFactorService;
use Golem15\User\Models\Settings as UserSettings;
use Golem15\User\Models\TwoFactorChallenge;
use Golem15\User\Models\TwoFactorMethod;
use Exception;

/**
 * TwoFactor component
 *
 * Handles 2FA verification during login and 2FA management for authenticated users.
 */
class TwoFactor extends ComponentBase
{
    protected TwoFactorService $service;

    public function init()
    {
        $this->service = app(TwoFactorService::class);
    }

    public function componentDetails()
    {
        return [
            'name' => 'golem15.user::lang.two_factor.component_name',
            'description' => 'golem15.user::lang.two_factor.component_description',
        ];
    }

    public function defineProperties()
    {
        return [
            'redirect' => [
                'title' => 'golem15.user::lang.account.redirect_to',
                'description' => 'golem15.user::lang.two_factor.redirect_after_verify',
                'type' => 'dropdown',
                'default' => '',
            ],
        ];
    }

    public function getRedirectOptions()
    {
        return ['' => '- refresh page -', '0' => '- no redirect -'] + Page::sortBy('baseFileName')->lists('baseFileName', 'baseFileName');
    }

    public function onRun()
    {
        $this->prepareVars();
    }

    public function prepareVars()
    {
        $this->page['user'] = $this->user();
        $this->page['challengeToken'] = session('2fa_challenge_token');
        $this->page['twoFactorStatus'] = $this->user() ? $this->service->getStatus($this->user()) : null;
        $this->page['passwordlessLoginEnabled'] = $this->service->isPasswordlessLoginEnabled();
    }

    public function user()
    {
        if (!Auth::check()) {
            return null;
        }
        return Auth::getUser();
    }

    // ========================================================================
    // Verification Handlers (during login flow)
    // ========================================================================

    /**
     * Verify a TOTP or email 2FA code during login.
     */
    public function onVerifyTwoFactor()
    {
        try {
            $challengeToken = post('challenge_token', session('2fa_challenge_token'));
            $method = post('method', 'totp');
            $code = post('code');

            if (!$challengeToken || !$code) {
                throw new ValidationException(['code' => 'Verification code is required.']);
            }

            $result = $this->service->verifyChallenge($challengeToken, $method, $code);

            if (!$result) {
                throw new ValidationException(['code' => 'Invalid verification code. Please try again.']);
            }

            // Log the user in via session
            $challenge = TwoFactorChallenge::where('token', $challengeToken)->first();
            if ($challenge) {
                $user = $challenge->user;
                $remember = session('2fa_remember', false);
                Auth::login($user, $remember);
                $this->handleTrustDevice($user);
            }

            // Clean up session
            session()->forget(['2fa_challenge_token', '2fa_remember']);

            Flash::success('Successfully verified.');

            if ($redirect = $this->makeRedirection()) {
                return $redirect;
            }

            return Redirect::refresh();
        } catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
        }
    }

    /**
     * Verify a WebAuthn assertion during login.
     */
    public function onVerifyWebAuthn()
    {
        try {
            $challengeToken = post('challenge_token', session('2fa_challenge_token'));
            $assertion = post('assertion');

            if (!$challengeToken || !$assertion) {
                throw new ValidationException(['assertion' => 'WebAuthn assertion is required.']);
            }

            $challenge = TwoFactorChallenge::findValidToken($challengeToken);
            if (!$challenge || !$challenge->code) {
                throw new ApplicationException('Invalid challenge. Please restart login.');
            }

            $result = $this->service->verifyChallenge(
                $challengeToken,
                TwoFactorMethod::METHOD_WEBAUTHN,
                is_string($assertion) ? $assertion : json_encode($assertion),
                ['challenge' => $challenge->code]
            );

            if (!$result) {
                throw new ValidationException(['assertion' => 'WebAuthn verification failed.']);
            }

            // Log the user in via session
            $user = $challenge->user;
            $remember = session('2fa_remember', false);
            Auth::login($user, $remember);
            $this->handleTrustDevice($user);

            session()->forget(['2fa_challenge_token', '2fa_remember']);
            Flash::success('Successfully verified.');

            if ($redirect = $this->makeRedirection()) {
                return $redirect;
            }

            return Redirect::refresh();
        } catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
        }
    }

    /**
     * Use a recovery code during login.
     */
    public function onUseRecoveryCode()
    {
        try {
            $challengeToken = post('challenge_token', session('2fa_challenge_token'));
            $code = post('recovery_code');

            if (!$challengeToken || !$code) {
                throw new ValidationException(['recovery_code' => 'Recovery code is required.']);
            }

            $result = $this->service->verifyChallenge($challengeToken, 'recovery', $code);

            if (!$result) {
                throw new ValidationException(['recovery_code' => 'Invalid recovery code.']);
            }

            $challenge = TwoFactorChallenge::where('token', $challengeToken)->first();
            if ($challenge) {
                $user = $challenge->user;
                $remember = session('2fa_remember', false);
                Auth::login($user, $remember);
                $this->handleTrustDevice($user);
            }

            session()->forget(['2fa_challenge_token', '2fa_remember']);
            Flash::success('Successfully verified with recovery code.');

            if ($redirect = $this->makeRedirection()) {
                return $redirect;
            }

            return Redirect::refresh();
        } catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
        }
    }

    /**
     * Request an email 2FA code.
     */
    public function onSendEmailCode()
    {
        try {
            $challengeToken = post('challenge_token', session('2fa_challenge_token'));

            if (!$challengeToken) {
                throw new ApplicationException('No active challenge.');
            }

            $challenge = TwoFactorChallenge::findValidToken($challengeToken);
            if (!$challenge) {
                throw new ApplicationException('Challenge expired. Please log in again.');
            }

            $maskedEmail = $this->service->sendEmailCode($challenge, $challenge->user);

            Flash::success("Verification code sent to {$maskedEmail}.");
        } catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
        }
    }

    /**
     * Get WebAuthn assertion options for verification.
     */
    public function onGetWebAuthnOptions()
    {
        $challengeToken = post('challenge_token', session('2fa_challenge_token'));

        $challenge = TwoFactorChallenge::findValidToken($challengeToken);
        if (!$challenge) {
            return response()->json(['error' => 'Challenge expired.'], 401);
        }

        $options = $this->service->getWebAuthnAuthenticationOptions($challenge->user);

        // Store WebAuthn challenge on the 2FA challenge
        $challenge->method = TwoFactorMethod::METHOD_WEBAUTHN;
        $challenge->code = $options['challenge'];
        $challenge->save();

        return $options;
    }

    // ========================================================================
    // Passwordless Login Handlers
    // ========================================================================

    /**
     * Get WebAuthn assertion options for passwordless login.
     */
    public function onPasswordlessOptions()
    {
        if (!$this->service->isPasswordlessLoginEnabled()) {
            throw new ApplicationException('Passwordless login is not enabled.');
        }

        $options = $this->service->getPasswordlessAuthenticationOptions();
        session(['passwordless_challenge' => $options['challenge']]);

        return $options;
    }

    /**
     * Verify a passwordless WebAuthn assertion and log the user in.
     */
    public function onPasswordlessVerify()
    {
        try {
            if (!$this->service->isPasswordlessLoginEnabled()) {
                throw new ApplicationException('Passwordless login is not enabled.');
            }

            $assertion = post('assertion');
            $challenge = session('passwordless_challenge');

            if (!$assertion || !$challenge) {
                throw new ApplicationException('Missing assertion data. Please try again.');
            }

            $user = $this->service->verifyPasswordlessAssertion(
                is_string($assertion) ? $assertion : json_encode($assertion),
                $challenge
            );

            if (!$user) {
                throw new ValidationException(['assertion' => 'Security key verification failed. Key not recognized.']);
            }

            if ($user->isBanned()) {
                throw new ApplicationException('This account is currently not activated.');
            }

            session()->forget('passwordless_challenge');

            // Log the user in
            Auth::login($user, true);

            if ($ipAddress = Request::ip()) {
                $user->touchIpAddress($ipAddress);
            }

            if ($redirect = $this->makeRedirection()) {
                return $redirect;
            }

            return Redirect::refresh();
        } catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
        }
    }

    // ========================================================================
    // Management Handlers (authenticated users)
    // ========================================================================

    /**
     * Begin TOTP setup - returns QR code data.
     */
    public function onSetupTotp()
    {
        try {
            if (!$user = $this->user()) {
                throw new ApplicationException('You must be logged in.');
            }

            $setupData = $this->service->setupTotp($user);

            $this->page['totpSetupData'] = $setupData;
            return ['#two-factor-setup' => $this->renderPartial('twofactor/setup_totp')];
        } catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
        }
    }

    /**
     * Confirm TOTP setup with a verification code.
     */
    public function onConfirmTotp()
    {
        try {
            if (!$user = $this->user()) {
                throw new ApplicationException('You must be logged in.');
            }

            $secret = post('totp_secret');
            $code = post('totp_code');

            if (!$secret || !$code) {
                throw new ValidationException(['totp_code' => 'Verification code is required.']);
            }

            $confirmed = $this->service->confirmTotp($user, $secret, $code);

            if (!$confirmed) {
                throw new ValidationException(['totp_code' => 'Invalid verification code.']);
            }

            Flash::success('Authenticator app enabled successfully.');
            $this->prepareVars();
            return ['#two-factor-manage' => $this->renderPartial('twofactor/default')];
        } catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
        }
    }

    /**
     * Enable email 2FA.
     */
    public function onEnableEmailTwoFactor()
    {
        try {
            if (!$user = $this->user()) {
                throw new ApplicationException('You must be logged in.');
            }

            $this->service->enableEmailMethod($user);

            Flash::success('Email verification enabled.');
            $this->prepareVars();
            return ['#two-factor-manage' => $this->renderPartial('twofactor/default')];
        } catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
        }
    }

    /**
     * Disable a 2FA method.
     */
    public function onDisableMethod()
    {
        try {
            if (!$user = $this->user()) {
                throw new ApplicationException('You must be logged in.');
            }

            $method = post('method');
            if (!$method) {
                throw new ApplicationException('Method is required.');
            }

            $this->service->disableMethod($user, $method);

            Flash::success('Two-factor method disabled.');
            $this->prepareVars();
            return ['#two-factor-manage' => $this->renderPartial('twofactor/default')];
        } catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
        }
    }

    /**
     * Get WebAuthn registration options.
     */
    public function onRegisterWebAuthnOptions()
    {
        if (!$user = $this->user()) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $options = $this->service->getWebAuthnRegistrationOptions($user);
        session(['webauthn_register_challenge' => $options['challenge']]);

        return $options;
    }

    /**
     * Complete WebAuthn registration.
     */
    public function onRegisterWebAuthn()
    {
        try {
            if (!$user = $this->user()) {
                throw new ApplicationException('You must be logged in.');
            }

            $attestation = post('attestation');
            $name = post('key_name');
            $challenge = session('webauthn_register_challenge');

            if (!$attestation || !$challenge) {
                throw new ApplicationException('Registration data missing. Please try again.');
            }

            if (is_string($attestation)) {
                $attestation = json_decode($attestation, true);
            }

            $this->service->registerWebAuthn($user, $attestation, $challenge, $name);
            session()->forget('webauthn_register_challenge');

            Flash::success('Security key registered successfully.');
            $this->prepareVars();
            return ['#two-factor-manage' => $this->renderPartial('twofactor/default')];
        } catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
        }
    }

    /**
     * Remove a WebAuthn credential.
     */
    public function onRemoveWebAuthn()
    {
        try {
            if (!$user = $this->user()) {
                throw new ApplicationException('You must be logged in.');
            }

            $credentialId = (int) post('credential_id');
            if (!$credentialId) {
                throw new ApplicationException('Credential ID is required.');
            }

            $this->service->removeWebAuthnCredential($user, $credentialId);

            Flash::success('Security key removed.');
            $this->prepareVars();
            return ['#two-factor-manage' => $this->renderPartial('twofactor/default')];
        } catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
        }
    }

    /**
     * Regenerate recovery codes (requires password confirmation).
     */
    public function onRegenerateRecoveryCodes()
    {
        try {
            if (!$user = $this->user()) {
                throw new ApplicationException('You must be logged in.');
            }

            $password = post('password');
            if (!$password || !$user->checkHashValue('password', $password)) {
                throw new ValidationException(['password' => 'Password confirmation required.']);
            }

            $codes = $this->service->generateRecoveryCodes($user);
            $this->page['recoveryCodes'] = $codes;

            Flash::success('New recovery codes generated. Save them securely.');
            return ['#recovery-codes-container' => $this->renderPartial('twofactor/recovery_codes')];
        } catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
        }
    }

    // ========================================================================
    // Trusted Device Handlers
    // ========================================================================

    /**
     * Revoke a single trusted device.
     */
    public function onRevokeTrustedDevice()
    {
        try {
            if (!$user = $this->user()) {
                throw new ApplicationException('You must be logged in.');
            }

            $deviceId = (int) post('device_id');
            if (!$deviceId) {
                throw new ApplicationException('Device ID is required.');
            }

            $this->service->revokeTrustedDevice($deviceId, $user);

            Flash::success('Trusted device revoked.');
            $this->prepareVars();
            return ['#two-factor-manage' => $this->renderPartial('twofactor/default')];
        } catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
        }
    }

    /**
     * Revoke all trusted devices.
     */
    public function onRevokeAllTrustedDevices()
    {
        try {
            if (!$user = $this->user()) {
                throw new ApplicationException('You must be logged in.');
            }

            $this->service->revokeAllTrustedDevices($user);

            Flash::success('All trusted devices revoked.');
            $this->prepareVars();
            return ['#two-factor-manage' => $this->renderPartial('twofactor/default')];
        } catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
        }
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    /**
     * Handle "trust this device" checkbox after successful 2FA verification.
     */
    protected function handleTrustDevice($user): void
    {
        if (post('trust_device') && $this->service->isTrustedDeviceEnabled()) {
            $this->service->createTrustedDevice($user);
        }
    }

    protected function makeRedirection()
    {
        $property = trim((string)$this->property('redirect'));

        if ($property === '0') {
            return;
        }

        if ($property === '') {
            return Redirect::refresh();
        }

        $redirectUrl = $this->pageUrl($property) ?: $property;

        if ($redirectUrl = post('redirect', $redirectUrl)) {
            return Redirect::intended($redirectUrl);
        }
    }
}
