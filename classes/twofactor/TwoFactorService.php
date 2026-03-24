<?php

namespace Golem15\User\Classes\TwoFactor;

use Cookie;
use Golem15\User\Models\Settings as UserSettings;
use Golem15\User\Models\TrustedDevice;
use Golem15\User\Models\TwoFactorChallenge;
use Golem15\User\Models\TwoFactorMethod;
use Golem15\User\Models\TwoFactorRecoveryCode;
use Golem15\User\Models\User;
use Golem15\User\Models\WebAuthnCredential;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Winter\Storm\Support\Facades\Event;

class TwoFactorService
{
    protected TotpMethod $totpMethod;
    protected EmailMethod $emailMethod;
    protected WebAuthnMethod $webAuthnMethod;

    public function __construct()
    {
        $this->totpMethod = new TotpMethod();
        $this->emailMethod = new EmailMethod();
        $this->webAuthnMethod = new WebAuthnMethod();
    }

    /**
     * Check if 2FA is enabled for a user.
     * Returns false for child accounts and when 2FA is globally disabled.
     */
    public function isEnabledForUser(User $user): bool
    {
        if ($this->isGloballyDisabled()) {
            return false;
        }

        // Children are exempt from 2FA
        if (method_exists($user, 'isChild') && $user->isChild()) {
            return false;
        }

        return TwoFactorMethod::where('user_id', $user->id)
            ->where('is_enabled', true)
            ->exists();
    }

    /**
     * Get list of enabled 2FA method types for a user.
     *
     * @return string[]
     */
    public function getEnabledMethods(User $user): array
    {
        $methods = TwoFactorMethod::where('user_id', $user->id)
            ->where('is_enabled', true)
            ->pluck('method')
            ->toArray();

        // For WebAuthn, also verify at least one credential exists
        if (in_array(TwoFactorMethod::METHOD_WEBAUTHN, $methods)) {
            if (!$this->webAuthnMethod->isConfiguredFor($user)) {
                $methods = array_values(array_diff($methods, [TwoFactorMethod::METHOD_WEBAUTHN]));
            }
        }

        return $methods;
    }

    /**
     * Check if 2FA is globally disabled.
     */
    public function isGloballyDisabled(): bool
    {
        return UserSettings::get('two_factor_mode', UserSettings::TWO_FACTOR_DISABLED) === UserSettings::TWO_FACTOR_DISABLED;
    }

    /**
     * Check if a specific method is available (enabled in global settings).
     */
    public function isMethodAvailable(string $method): bool
    {
        if ($this->isGloballyDisabled()) {
            return false;
        }

        $availableMethods = UserSettings::get('two_factor_available_methods', ['totp', 'email']);
        return in_array($method, $availableMethods);
    }

    /**
     * Check if 2FA is enforced for a user (based on group membership).
     */
    public function isEnforcedForUser(User $user): bool
    {
        $mode = UserSettings::get('two_factor_mode', UserSettings::TWO_FACTOR_DISABLED);
        if ($mode !== UserSettings::TWO_FACTOR_ENFORCED) {
            return false;
        }

        $enforcedGroups = UserSettings::get('two_factor_enforce_groups', []);
        if (empty($enforcedGroups)) {
            return true; // Enforced for all users
        }

        $userGroupCodes = $user->groups->pluck('code')->toArray();
        return !empty(array_intersect($userGroupCodes, $enforcedGroups));
    }

    /**
     * Create a 2FA challenge after successful password verification.
     */
    public function createChallenge(User $user, ?string $ipAddress = null, ?string $userAgent = null): TwoFactorChallenge
    {
        $ttl = (int) UserSettings::get('two_factor_challenge_ttl', 5);

        $challenge = TwoFactorChallenge::generate($user, $ipAddress, $userAgent, $ttl);

        Event::fire('golem15.user.2fa.challenged', [$user, $challenge]);

        return $challenge;
    }

    /**
     * Verify a 2FA challenge. On success, issues a real JWT token.
     *
     * @param string $token Challenge token
     * @param string $method 2FA method used ('totp', 'email', 'webauthn', 'recovery')
     * @param string $code Verification code or assertion data
     * @param array|null $context Additional context (WebAuthn challenge, etc.)
     * @return array|false Returns ['token' => jwt, 'user' => apiArray] or false
     */
    public function verifyChallenge(string $token, string $method, string $code, ?array $context = null)
    {
        $challenge = TwoFactorChallenge::findValidToken($token);
        if (!$challenge) {
            return false;
        }

        $user = $challenge->user;
        if (!$user) {
            return false;
        }

        $challenge->incrementAttempts();

        // Check if exhausted after incrementing
        if ($challenge->isExhausted()) {
            Event::fire('golem15.user.2fa.failed', [$user, $method, $challenge->ip_address]);
            return false;
        }

        $verified = false;

        if ($method === 'recovery') {
            $verified = TwoFactorRecoveryCode::verifyAndConsume($user->id, $code);
            if ($verified) {
                $remaining = TwoFactorRecoveryCode::remainingCount($user->id);
                Event::fire('golem15.user.2fa.recovery_used', [$user, $remaining]);
            }
        } else {
            $methodHandler = $this->getMethodHandler($method);
            if (!$methodHandler) {
                return false;
            }

            // For email method, pass the challenge in context
            if ($method === TwoFactorMethod::METHOD_EMAIL) {
                $context = array_merge($context ?? [], ['challenge' => $challenge]);
            }

            $verified = $methodHandler->verify($user, $code, $context);

            if ($verified) {
                // Update last_used_at on the method
                $methodModel = TwoFactorMethod::where('user_id', $user->id)
                    ->where('method', $method)
                    ->where('is_enabled', true)
                    ->first();

                if ($methodModel) {
                    $methodModel->touchLastUsed();
                }
            }
        }

        if (!$verified) {
            Event::fire('golem15.user.2fa.failed', [$user, $method, $challenge->ip_address]);
            return false;
        }

        // Mark challenge as completed
        $challenge->markCompleted();

        // Issue real JWT
        $jwtToken = JWTAuth::fromUser($user);
        event('golem15.user.login', [$user]);
        Event::fire('golem15.user.2fa.verified', [$user, $method]);

        return [
            'token' => $jwtToken,
            'user' => $user->getApiArray(),
        ];
    }

    /**
     * Send an email 2FA code for a challenge.
     *
     * @return string Masked email address
     */
    public function sendEmailCode(TwoFactorChallenge $challenge, User $user): string
    {
        return $this->emailMethod->sendCode($challenge, $user);
    }

    /**
     * Set up TOTP for a user (returns QR code, does NOT enable yet).
     */
    public function setupTotp(User $user): array
    {
        return $this->totpMethod->setup($user);
    }

    /**
     * Confirm and enable TOTP after verifying the initial code.
     */
    public function confirmTotp(User $user, string $secret, string $code): bool
    {
        if (!$this->totpMethod->verifyAgainstSecret($secret, $code)) {
            return false;
        }

        $method = TwoFactorMethod::updateOrCreate(
            ['user_id' => $user->id, 'method' => TwoFactorMethod::METHOD_TOTP],
            ['is_enabled' => true, 'secret' => $secret]
        );

        // Generate recovery codes if this is the first 2FA method
        $this->ensureRecoveryCodes($user);

        Event::fire('golem15.user.2fa.enabled', [$user, TwoFactorMethod::METHOD_TOTP]);

        return true;
    }

    /**
     * Enable email 2FA for a user.
     */
    public function enableEmailMethod(User $user): bool
    {
        TwoFactorMethod::updateOrCreate(
            ['user_id' => $user->id, 'method' => TwoFactorMethod::METHOD_EMAIL],
            ['is_enabled' => true]
        );

        $this->ensureRecoveryCodes($user);

        Event::fire('golem15.user.2fa.enabled', [$user, TwoFactorMethod::METHOD_EMAIL]);

        return true;
    }

    /**
     * Disable a 2FA method for a user.
     */
    public function disableMethod(User $user, string $method): bool
    {
        $methodModel = TwoFactorMethod::where('user_id', $user->id)
            ->where('method', $method)
            ->first();

        if (!$methodModel) {
            return false;
        }

        if ($method === TwoFactorMethod::METHOD_WEBAUTHN) {
            // Disable all WebAuthn credentials
            WebAuthnCredential::where('user_id', $user->id)->update(['is_enabled' => false]);
        }

        $methodModel->is_enabled = false;
        $methodModel->save();

        Event::fire('golem15.user.2fa.disabled', [$user, $method]);

        // If no 2FA methods remain, clean up recovery codes and trusted devices
        if (!$this->isEnabledForUser($user)) {
            TwoFactorRecoveryCode::where('user_id', $user->id)->delete();
            TrustedDevice::where('user_id', $user->id)->delete();
        }

        return true;
    }

    /**
     * Get WebAuthn registration options.
     */
    public function getWebAuthnRegistrationOptions(User $user): array
    {
        $passwordlessEnabled = UserSettings::get('two_factor_passwordless_login', false);
        return $this->webAuthnMethod->getRegistrationOptions($user, $passwordlessEnabled);
    }

    /**
     * Complete WebAuthn registration.
     */
    public function registerWebAuthn(User $user, array $response, string $challenge, ?string $name = null): WebAuthnCredential
    {
        $credential = $this->webAuthnMethod->verifyRegistration($user, $response, $challenge, $name);

        $this->ensureRecoveryCodes($user);

        Event::fire('golem15.user.2fa.webauthn.registered', [$user, $credential]);

        return $credential;
    }

    /**
     * Remove a WebAuthn credential.
     */
    public function removeWebAuthnCredential(User $user, int $credentialId): bool
    {
        $credential = WebAuthnCredential::where('id', $credentialId)
            ->where('user_id', $user->id)
            ->first();

        if (!$credential) {
            return false;
        }

        $credential->delete();

        Event::fire('golem15.user.2fa.webauthn.removed', [$user, $credentialId]);

        // If no more WebAuthn credentials, disable the method
        if (!$this->webAuthnMethod->isConfiguredFor($user)) {
            $methodModel = TwoFactorMethod::where('user_id', $user->id)
                ->where('method', TwoFactorMethod::METHOD_WEBAUTHN)
                ->first();

            if ($methodModel) {
                $methodModel->is_enabled = false;
                $methodModel->save();
                Event::fire('golem15.user.2fa.disabled', [$user, TwoFactorMethod::METHOD_WEBAUTHN]);
            }
        }

        // If no 2FA methods remain, clean up recovery codes and trusted devices
        if (!$this->isEnabledForUser($user)) {
            TwoFactorRecoveryCode::where('user_id', $user->id)->delete();
            TrustedDevice::where('user_id', $user->id)->delete();
        }

        return true;
    }

    /**
     * Get WebAuthn authentication options for a challenge.
     */
    public function getWebAuthnAuthenticationOptions(User $user): array
    {
        return $this->webAuthnMethod->getAuthenticationOptions($user);
    }

    /**
     * Check if passwordless security key login is enabled.
     */
    public function isPasswordlessLoginEnabled(): bool
    {
        return (bool) UserSettings::get('two_factor_passwordless_login', false);
    }

    /**
     * Get WebAuthn assertion options for passwordless login.
     */
    public function getPasswordlessAuthenticationOptions(): array
    {
        return $this->webAuthnMethod->getPasswordlessAuthenticationOptions();
    }

    /**
     * Verify a passwordless WebAuthn assertion and return the user.
     */
    public function verifyPasswordlessAssertion(string $assertionJson, string $challenge): ?User
    {
        return $this->webAuthnMethod->verifyPasswordlessAssertion($assertionJson, $challenge);
    }

    // ========================================================================
    // Trusted Device Methods
    // ========================================================================

    /**
     * Check if trusted device feature is enabled.
     */
    public function isTrustedDeviceEnabled(): bool
    {
        return (bool) UserSettings::get('trusted_device_enabled', false);
    }

    /**
     * Get the configured trust duration in days.
     */
    public function getTrustedDeviceTtlDays(): int
    {
        return (int) UserSettings::get('trusted_device_ttl_days', 30);
    }

    /**
     * Check if the current request has a valid trusted device cookie.
     */
    public function checkTrustedDevice(int $userId): bool
    {
        $cookieValue = request()->cookie('g15_trusted_device');
        if (!$cookieValue) {
            return false;
        }

        $parts = explode('|', $cookieValue);
        if (count($parts) !== 3) {
            return false;
        }

        [$cookieUserId, $cookieToken, $hmac] = $parts;

        // Validate HMAC
        $expectedHmac = hash_hmac('sha256', "{$cookieUserId}|{$cookieToken}", config('app.key'));
        if (!hash_equals($expectedHmac, $hmac)) {
            return false;
        }

        // Validate user ID matches
        if ((int) $cookieUserId !== $userId) {
            return false;
        }

        // Look up token in database
        $device = TrustedDevice::findValidToken($cookieToken);
        if (!$device || $device->user_id !== $userId) {
            return false;
        }

        // Update last used
        $device->last_used_at = now();
        $device->ip_address = request()->ip();
        $device->save();

        return true;
    }

    /**
     * Create a trusted device record and queue the cookie.
     */
    public function createTrustedDevice(User $user): void
    {
        $ttlDays = $this->getTrustedDeviceTtlDays();
        $device = TrustedDevice::createForUser(
            $user,
            $ttlDays,
            request()->userAgent(),
            request()->ip()
        );

        $cookieValue = "{$user->id}|{$device->token}|" . hash_hmac('sha256', "{$user->id}|{$device->token}", config('app.key'));

        Cookie::queue(
            'g15_trusted_device',
            $cookieValue,
            $ttlDays * 24 * 60, // minutes
            '/',
            null,
            request()->isSecure(),
            true, // httpOnly
            false,
            'Lax'
        );
    }

    /**
     * Create a trusted device record and return the token (for API/SPA use without cookies).
     */
    public function createTrustedDeviceToken(User $user): string
    {
        $ttlDays = $this->getTrustedDeviceTtlDays();
        $device = TrustedDevice::createForUser(
            $user,
            $ttlDays,
            request()->userAgent(),
            request()->ip()
        );

        return $device->token;
    }

    /**
     * Validate a trusted device token for a user (token-based, no cookie).
     */
    public function checkTrustedDeviceToken(int $userId, string $token): bool
    {
        $device = TrustedDevice::findValidToken($token);
        if (!$device || $device->user_id !== $userId) {
            return false;
        }

        $device->last_used_at = now();
        $device->ip_address = request()->ip();
        $device->save();

        return true;
    }

    /**
     * Revoke a single trusted device.
     */
    public function revokeTrustedDevice(int $deviceId, User $user): bool
    {
        return (bool) TrustedDevice::where('id', $deviceId)
            ->where('user_id', $user->id)
            ->delete();
    }

    /**
     * Revoke all trusted devices for a user and clear the cookie.
     */
    public function revokeAllTrustedDevices(User $user): int
    {
        Cookie::queue(Cookie::forget('g15_trusted_device'));
        return TrustedDevice::where('user_id', $user->id)->delete();
    }

    /**
     * Generate recovery codes for a user.
     *
     * @return string[] Plaintext codes (shown to user once)
     */
    public function generateRecoveryCodes(User $user, int $count = 10): array
    {
        $codes = TwoFactorRecoveryCode::generateForUser($user->id, $count);

        Event::fire('golem15.user.2fa.recovery_regenerated', [$user]);

        return $codes;
    }

    /**
     * Get the 2FA status for a user.
     */
    public function getStatus(User $user): array
    {
        $methods = TwoFactorMethod::where('user_id', $user->id)
            ->where('is_enabled', true)
            ->get();

        $webauthnCredentials = WebAuthnCredential::where('user_id', $user->id)
            ->where('is_enabled', true)
            ->get()
            ->map(function ($cred) {
                return [
                    'id' => $cred->id,
                    'name' => $cred->name ?? 'Security Key',
                    'last_used_at' => $cred->last_used_at?->toIso8601String(),
                    'created_at' => $cred->created_at?->toIso8601String(),
                ];
            });

        $recoveryCodesRemaining = TwoFactorRecoveryCode::remainingCount($user->id);

        $trustedDevices = $this->isTrustedDeviceEnabled()
            ? TrustedDevice::where('user_id', $user->id)
                ->where('trusted_until', '>', now())
                ->orderBy('last_used_at', 'desc')
                ->get()
                ->map(fn($d) => [
                    'id' => $d->id,
                    'device_name' => $d->device_name ?? 'Unknown Device',
                    'ip_address' => $d->ip_address,
                    'last_used_at' => $d->last_used_at,
                    'trusted_until' => $d->trusted_until,
                    'created_at' => $d->created_at,
                ])->toArray()
            : [];

        return [
            'enabled' => $this->isEnabledForUser($user),
            'enforced' => $this->isEnforcedForUser($user),
            'methods' => $methods->pluck('method')->toArray(),
            'webauthn_credentials' => $webauthnCredentials->toArray(),
            'recovery_codes_remaining' => $recoveryCodesRemaining,
            'available_methods' => UserSettings::get('two_factor_available_methods', ['totp', 'email']),
            'trusted_device_enabled' => $this->isTrustedDeviceEnabled(),
            'trusted_devices' => $trustedDevices,
        ];
    }

    /**
     * Ensure recovery codes exist when enabling a 2FA method.
     */
    protected function ensureRecoveryCodes(User $user): void
    {
        $hasExistingCodes = TwoFactorRecoveryCode::where('user_id', $user->id)
            ->whereNull('used_at')
            ->exists();

        if (!$hasExistingCodes) {
            TwoFactorRecoveryCode::generateForUser($user->id);
        }
    }

    /**
     * Get the method handler for a given method type.
     */
    protected function getMethodHandler(string $method): ?object
    {
        return match ($method) {
            TwoFactorMethod::METHOD_TOTP => $this->totpMethod,
            TwoFactorMethod::METHOD_EMAIL => $this->emailMethod,
            TwoFactorMethod::METHOD_WEBAUTHN => $this->webAuthnMethod,
            default => null,
        };
    }
}
