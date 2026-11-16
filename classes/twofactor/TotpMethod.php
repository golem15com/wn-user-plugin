<?php

namespace Golem15\User\Classes\TwoFactor;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Golem15\User\Contracts\TwoFactorMethodInterface;
use Golem15\User\Models\TwoFactorMethod;
use Golem15\User\Models\User;
use PragmaRX\Google2FA\Google2FA;

class TotpMethod implements TwoFactorMethodInterface
{
    protected Google2FA $google2fa;

    public function __construct()
    {
        $this->google2fa = new Google2FA();
    }

    public function getMethodName(): string
    {
        return TwoFactorMethod::METHOD_TOTP;
    }

    /**
     * Set up TOTP for a user. Generates a secret and QR code.
     * The secret is NOT saved yet -- caller must confirm with a valid code first.
     *
     * @return array{secret: string, qr_code_svg: string, qr_code_url: string}
     */
    public function setup(User $user): array
    {
        $secret = $this->google2fa->generateSecretKey();
        $issuer = config('app.name', 'Golem15');
        $holder = $user->email;

        $qrCodeUrl = $this->google2fa->getQRCodeUrl($issuer, $holder, $secret);

        $renderer = new ImageRenderer(
            new RendererStyle(200),
            new SvgImageBackEnd()
        );
        $writer = new Writer($renderer);
        $qrCodeSvg = $writer->writeString($qrCodeUrl);

        return [
            'secret' => $secret,
            'qr_code_svg' => $qrCodeSvg,
            'qr_code_url' => $qrCodeUrl,
        ];
    }

    /**
     * Verify a TOTP code against the user's stored secret.
     * Window of 1 allows codes from 30 seconds before/after.
     *
     * Replay guard (always on, D-28): a code is accepted only when its timestep is
     * newer than the last accepted one for this method row, and the new timestep is
     * claimed with one conditional UPDATE. Two concurrent requests carrying the same
     * code race on that UPDATE and only one of them affects the row.
     */
    public function verify(User $user, string $code, ?array $context = null): bool
    {
        $method = TwoFactorMethod::where('user_id', $user->id)
            ->where('method', $this->getMethodName())
            ->where('is_enabled', true)
            ->first();

        if (!$method || !$method->secret) {
            return false;
        }

        $timestep = $this->timestepFor($method->secret, $code, (int) ($method->last_totp_timestep ?? 0));
        if ($timestep === false) {
            return false;
        }

        $claimed = TwoFactorMethod::where('id', $method->id)
            ->where(function ($query) use ($timestep) {
                $query->whereNull('last_totp_timestep')
                    ->orWhere('last_totp_timestep', '<', $timestep);
            })
            ->update(['last_totp_timestep' => $timestep]);

        return $claimed === 1;
    }

    /**
     * Return the timestep a valid code belongs to, or false.
     *
     * Only timesteps newer than $after match. $after is always passed to google2fa
     * as an int: with a null old timestamp verifyKeyNewer() returns boolean true
     * instead of the matched timestep.
     */
    public function timestepFor(string $secret, string $code, int $after = 0): int|false
    {
        $result = $this->google2fa->verifyKeyNewer($secret, $code, $after, 1);

        if ($result === false || $result === true) {
            return false;
        }

        return (int) $result;
    }

    /**
     * Verify a TOTP code against a specific secret (used during setup confirmation).
     */
    public function verifyAgainstSecret(string $secret, string $code): bool
    {
        return $this->google2fa->verifyKey($secret, $code, 1);
    }

    public function isConfiguredFor(User $user): bool
    {
        return TwoFactorMethod::where('user_id', $user->id)
            ->where('method', $this->getMethodName())
            ->where('is_enabled', true)
            ->whereNotNull('secret')
            ->exists();
    }
}
