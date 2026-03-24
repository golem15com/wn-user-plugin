<?php

namespace Golem15\User\Classes\TwoFactor;

use Golem15\User\Contracts\TwoFactorMethodInterface;
use Golem15\User\Models\Settings as UserSettings;
use Golem15\User\Models\TwoFactorChallenge;
use Golem15\User\Models\TwoFactorMethod;
use Golem15\User\Models\User;
use Illuminate\Support\Facades\Mail;

class EmailMethod implements TwoFactorMethodInterface
{
    public function getMethodName(): string
    {
        return TwoFactorMethod::METHOD_EMAIL;
    }

    /**
     * No special setup needed for email 2FA -- uses the user's verified email.
     */
    public function setup(User $user): array
    {
        return [
            'email' => $this->maskEmail($user->email),
        ];
    }

    /**
     * Verify email code against the challenge's stored hash.
     */
    public function verify(User $user, string $code, ?array $context = null): bool
    {
        if (!isset($context['challenge']) || !$context['challenge'] instanceof TwoFactorChallenge) {
            return false;
        }

        return $context['challenge']->verifyEmailCode($code);
    }

    public function isConfiguredFor(User $user): bool
    {
        return TwoFactorMethod::where('user_id', $user->id)
            ->where('method', $this->getMethodName())
            ->where('is_enabled', true)
            ->exists();
    }

    /**
     * Generate and send a 6-digit verification code via email.
     */
    public function sendCode(TwoFactorChallenge $challenge, User $user): string
    {
        $code = $this->generateCode();
        $challenge->setEmailCode($code);

        $ttl = UserSettings::get('two_factor_email_code_ttl', 10);

        Mail::send('golem15.user::mail.two_factor_code', [
            'name' => $user->name,
            'code' => $code,
            'expiry_minutes' => $ttl,
        ], function ($message) use ($user) {
            $message->to($user->email, $user->name);
        });

        return $this->maskEmail($user->email);
    }

    /**
     * Generate a random 6-digit numeric code.
     */
    protected function generateCode(): string
    {
        return str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Mask email for display: j***n@example.com
     */
    protected function maskEmail(string $email): string
    {
        $parts = explode('@', $email);
        if (count($parts) !== 2) {
            return '***';
        }

        $local = $parts[0];
        $domain = $parts[1];

        if (strlen($local) <= 2) {
            $masked = $local[0] . '***';
        } else {
            $masked = $local[0] . str_repeat('*', strlen($local) - 2) . $local[strlen($local) - 1];
        }

        return $masked . '@' . $domain;
    }
}
