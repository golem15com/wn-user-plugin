<?php

namespace Golem15\User\Classes\TwoFactor;

use Golem15\User\Contracts\TwoFactorMethodInterface;
use Golem15\User\Models\TwoFactorMethod;
use Golem15\User\Models\User;
use Golem15\User\Models\WebAuthnCredential;
use lbuchs\WebAuthn\WebAuthn;
use lbuchs\WebAuthn\Binary\ByteBuffer;

class WebAuthnMethod implements TwoFactorMethodInterface
{
    protected WebAuthn $webAuthn;

    public function __construct()
    {
        $rpName = config('app.name', 'Golem15');
        $rpId = $this->getRpId();
        $this->webAuthn = new WebAuthn($rpName, $rpId, ['none']);
    }

    public function getMethodName(): string
    {
        return TwoFactorMethod::METHOD_WEBAUTHN;
    }

    /**
     * Setup returns info about WebAuthn capability; actual registration
     * is done via getRegistrationOptions() + verifyRegistration().
     */
    public function setup(User $user): array
    {
        return [
            'rp_id' => $this->getRpId(),
            'rp_name' => config('app.name', 'Golem15'),
        ];
    }

    /**
     * Verify a WebAuthn assertion.
     *
     * @param User $user
     * @param string $code JSON-encoded client assertion data
     * @param array|null $context Must contain 'challenge' key with base64url challenge
     * @return bool
     */
    public function verify(User $user, string $code, ?array $context = null): bool
    {
        if (!isset($context['challenge'])) {
            return false;
        }

        try {
            $clientData = json_decode($code, true);
            if (!$clientData) {
                return false;
            }

            $credentialId = $clientData['id'] ?? '';
            $clientDataJSON = $clientData['response']['clientDataJSON'] ?? '';
            $authenticatorData = $clientData['response']['authenticatorData'] ?? '';
            $signature = $clientData['response']['signature'] ?? '';

            // Find the credential
            $credential = WebAuthnCredential::where('user_id', $user->id)
                ->where('is_enabled', true)
                ->get()
                ->first(function ($cred) use ($credentialId) {
                    return $cred->credential_id === $credentialId;
                });

            if (!$credential) {
                return false;
            }

            $challenge = new ByteBuffer(base64_decode($context['challenge']));

            $credentialPublicKey = base64_decode($credential->public_key);

            $this->webAuthn->processGet(
                base64_decode($clientDataJSON),
                base64_decode($authenticatorData),
                base64_decode($signature),
                $credentialPublicKey,
                $challenge,
                null,
                $context['requireUserVerification'] ?? false
            );

            // Update sign count
            $newSignCount = $this->webAuthn->getSignatureCounter();
            if ($newSignCount > 0) {
                $credential->touchUsed($newSignCount);
            } else {
                $credential->last_used_at = now();
                $credential->save();
            }

            return true;
        } catch (\Exception $e) {
            \Log::warning('WebAuthn verification failed', [
                'user_id' => $user->id,
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    /**
     * Get registration options for creating a new WebAuthn credential.
     *
     * @return array{options: mixed, challenge: string}
     */
    public function getRegistrationOptions(User $user): array
    {
        // Get existing credential IDs to exclude
        $existingCredentials = WebAuthnCredential::where('user_id', $user->id)
            ->where('is_enabled', true)
            ->get()
            ->map(function ($cred) {
                return new ByteBuffer(base64_decode($cred->credential_id));
            })
            ->toArray();

        $createArgs = $this->webAuthn->getCreateArgs(
            \hex2bin(str_pad(dechex($user->id), 16, '0', STR_PAD_LEFT)),
            $user->name ?? $user->email,
            $user->email,
            60,
            false,      // requireResidentKey
            false,      // requireUserVerification
            $existingCredentials ?: null
        );

        // Store challenge for verification
        $challenge = base64_encode($this->webAuthn->getChallenge()->getBinaryString());

        return [
            'options' => $createArgs,
            'challenge' => $challenge,
        ];
    }

    /**
     * Verify and store a new WebAuthn registration response.
     *
     * @param User $user
     * @param array $response Client attestation response data
     * @param string $challenge Base64-encoded challenge from getRegistrationOptions
     * @param string|null $name User-given name for this credential
     * @return WebAuthnCredential
     */
    public function verifyRegistration(User $user, array $response, string $challenge, ?string $name = null): WebAuthnCredential
    {
        $clientDataJSON = base64_decode($response['clientDataJSON'] ?? '');
        $attestationObject = base64_decode($response['attestationObject'] ?? '');

        $challengeBuffer = new ByteBuffer(base64_decode($challenge));

        $data = $this->webAuthn->processCreate(
            $clientDataJSON,
            $attestationObject,
            $challengeBuffer,
            false,  // requireUserVerification
            true,   // requireUserPresent
            false   // failIfRootMismatch
        );

        $credential = WebAuthnCredential::create([
            'user_id' => $user->id,
            'credential_id' => base64_encode($data->credentialId->getBinaryString()),
            'public_key' => base64_encode($data->credentialPublicKey),
            'attestation_type' => $data->attestationFormat ?? 'none',
            'transports' => $response['transports'] ?? null,
            'sign_count' => $data->signatureCounter ?? 0,
            'name' => $name,
            'is_enabled' => true,
        ]);

        // Ensure the webauthn TwoFactorMethod record exists
        TwoFactorMethod::firstOrCreate(
            ['user_id' => $user->id, 'method' => TwoFactorMethod::METHOD_WEBAUTHN],
            ['is_enabled' => true]
        );

        return $credential;
    }

    /**
     * Get authentication/assertion options for verifying a WebAuthn credential.
     *
     * @return array{options: mixed, challenge: string}
     */
    public function getAuthenticationOptions(User $user): array
    {
        $credentials = WebAuthnCredential::where('user_id', $user->id)
            ->where('is_enabled', true)
            ->get()
            ->map(function ($cred) {
                return [
                    'id' => new ByteBuffer(base64_decode($cred->credential_id)),
                    'transports' => $cred->transports ?? [],
                ];
            })
            ->toArray();

        $getArgs = $this->webAuthn->getGetArgs(
            array_map(fn($c) => $c['id'], $credentials),
            60,
            false,  // requireUserVerification
            null    // allowedTransports determined per credential
        );

        $challenge = base64_encode($this->webAuthn->getChallenge()->getBinaryString());

        return [
            'options' => $getArgs,
            'challenge' => $challenge,
        ];
    }

    public function isConfiguredFor(User $user): bool
    {
        return WebAuthnCredential::where('user_id', $user->id)
            ->where('is_enabled', true)
            ->exists();
    }

    /**
     * Get the Relying Party ID from the app URL.
     */
    protected function getRpId(): string
    {
        $url = config('app.url', 'localhost');
        $parsed = parse_url($url);
        return $parsed['host'] ?? 'localhost';
    }
}
