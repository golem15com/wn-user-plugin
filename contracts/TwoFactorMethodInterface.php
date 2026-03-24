<?php

namespace Golem15\User\Contracts;

use Golem15\User\Models\User;

interface TwoFactorMethodInterface
{
    /**
     * Get the method identifier (e.g., 'totp', 'webauthn', 'email').
     */
    public function getMethodName(): string;

    /**
     * Set up this 2FA method for a user.
     * Returns method-specific setup data (e.g., QR code, secret).
     */
    public function setup(User $user): array;

    /**
     * Verify a 2FA code/assertion for the user.
     *
     * @param User $user
     * @param string $code The verification code or assertion data
     * @param array|null $context Additional context (e.g., WebAuthn assertion response)
     * @return bool
     */
    public function verify(User $user, string $code, ?array $context = null): bool;

    /**
     * Check if this method is configured and ready for the given user.
     */
    public function isConfiguredFor(User $user): bool;
}
