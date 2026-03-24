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

        return $this->google2fa->verifyKey($method->secret, $code, 1);
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
