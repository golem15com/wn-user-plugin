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
                clientDataJSON: base64_decode($clientDataJSON),
                authenticatorData: base64_decode($authenticatorData),
                signature: base64_decode($signature),
                credentialPublicKey: $credentialPublicKey,
                challenge: $challenge,
                prevSignatureCnt: null,
                requireUserVerification: (bool) ($context['requireUserVerification'] ?? false) || $this->requiresUserVerification()
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
    public function getRegistrationOptions(User $user, bool $discoverable = false): array
    {
        // Get existing credential IDs to exclude
        $existingCredentials = WebAuthnCredential::where('user_id', $user->id)
            ->where('is_enabled', true)
            ->get()
            ->map(function ($cred) {
                return new ByteBuffer(base64_decode($cred->credential_id));
            })
            ->toArray();

        // Named arguments: the positional call passed the exclude list into
        // $crossPlatformAttachment, so excludeCredentials was never sent. No
        // crossPlatformAttachment: platform and roaming authenticators are both allowed.
        $createArgs = $this->webAuthn->getCreateArgs(
            userId: $this->userHandleFor($user->id),
            userName: $user->name ?? $user->email,
            userDisplayName: $user->email,
            timeout: 60,
            requireResidentKey: $this->residentKey($discoverable),
            requireUserVerification: $this->userVerification(),
            excludeCredentialIds: $existingCredentials
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
            clientDataJSON: $clientDataJSON,
            attestationObject: $attestationObject,
            challenge: $challengeBuffer,
            requireUserVerification: $this->requiresUserVerification(),
            requireUserPresent: true,
            failIfRootMismatch: false
        );

        $credential = WebAuthnCredential::create([
            'user_id' => $user->id,
            'credential_id' => base64_encode($data->credentialId instanceof ByteBuffer ? $data->credentialId->getBinaryString() : $data->credentialId),
            'public_key' => base64_encode($data->credentialPublicKey),
            'attestation_type' => $data->attestationFormat ?? 'none',
            'transports' => $response['transports'] ?? null,
            'sign_count' => $data->signatureCounter ?? 0,
            'name' => $name,
            'is_enabled' => true,
        ]);

        // Ensure the webauthn TwoFactorMethod record exists and is enabled: after
        // every key was removed the row is disabled, and a new passkey must turn
        // two-factor back on (D-08).
        TwoFactorMethod::updateOrCreate(
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

        // Named arguments: the positional call passed false/null into
        // $allowUsb/$allowNfc, which dropped the usb and nfc transport hints.
        $getArgs = $this->webAuthn->getGetArgs(
            credentialIds: array_map(fn($c) => $c['id'], $credentials),
            timeout: 60,
            requireUserVerification: $this->userVerification()
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
     * Get assertion options for passwordless login (no user specified, empty allowCredentials).
     *
     * @return array{options: mixed, challenge: string}
     */
    public function getPasswordlessAuthenticationOptions(): array
    {
        $getArgs = $this->webAuthn->getGetArgs(
            credentialIds: [],     // empty allowCredentials — browser discovers passkeys
            timeout: 60,
            requireUserVerification: $this->userVerification()
        );

        $challenge = base64_encode($this->webAuthn->getChallenge()->getBinaryString());

        return [
            'options' => $getArgs,
            'challenge' => $challenge,
        ];
    }

    /**
     * Verify a passwordless assertion and return the matching user.
     *
     * @param string $assertionJson JSON-encoded client assertion data
     * @param string $challenge Base64-encoded challenge
     * @return User|null
     */
    public function verifyPasswordlessAssertion(string $assertionJson, string $challenge): ?User
    {
        try {
            $clientData = json_decode($assertionJson, true);
            if (!$clientData) {
                return null;
            }

            $credentialId = $clientData['id'] ?? '';
            $clientDataJSON = $clientData['response']['clientDataJSON'] ?? '';
            $authenticatorData = $clientData['response']['authenticatorData'] ?? '';
            $signature = $clientData['response']['signature'] ?? '';

            // Find the credential across all users
            $credential = WebAuthnCredential::where('is_enabled', true)
                ->get()
                ->first(function ($cred) use ($credentialId) {
                    return $cred->credential_id === $credentialId;
                });

            if (!$credential) {
                return null;
            }

            $challengeBuffer = new ByteBuffer(base64_decode($challenge));
            $credentialPublicKey = base64_decode($credential->public_key);

            $this->webAuthn->processGet(
                clientDataJSON: base64_decode($clientDataJSON),
                authenticatorData: base64_decode($authenticatorData),
                signature: base64_decode($signature),
                credentialPublicKey: $credentialPublicKey,
                challenge: $challengeBuffer,
                prevSignatureCnt: null,
                requireUserVerification: $this->requiresUserVerification()
            );

            // Update sign count
            $newSignCount = $this->webAuthn->getSignatureCounter();
            if ($newSignCount > 0) {
                $credential->touchUsed($newSignCount);
            } else {
                $credential->last_used_at = now();
                $credential->save();
            }

            return User::find($credential->user_id);
        } catch (\Exception $e) {
            \Log::warning('Passwordless WebAuthn verification failed', [
                'error' => $e->getMessage(),
            ]);
            return null;
        }
    }

    /**
     * The user handle bound to a credential at registration (8 bytes, big-endian user id).
     */
    public function userHandleFor(int $userId): string
    {
        return \hex2bin(str_pad(dechex($userId), 16, '0', STR_PAD_LEFT));
    }

    /**
     * Get the Relying Party ID: config golem15.user::webAuthnRpId when set,
     * otherwise the host of app.url (the behaviour before the key existed).
     */
    protected function getRpId(): string
    {
        $configured = trim((string) config('golem15.user::webAuthnRpId', ''));
        if ($configured !== '') {
            return $configured;
        }

        $url = config('app.url', 'localhost');
        $parsed = parse_url($url);
        return $parsed['host'] ?? 'localhost';
    }

    /**
     * Configured user-verification requirement (required|preferred|discouraged),
     * "preferred" when unset or invalid.
     */
    protected function userVerification(): string
    {
        $value = strtolower(trim((string) config('golem15.user::webAuthnUserVerification', 'preferred')));

        return in_array($value, ['required', 'preferred', 'discouraged'], true) ? $value : 'preferred';
    }

    /**
     * Whether the server must reject a response without the UV flag.
     */
    protected function requiresUserVerification(): bool
    {
        return $this->userVerification() === 'required';
    }

    /**
     * Resident-key requirement for registration. A valid configured value wins;
     * otherwise "preferred" for discoverable (passwordless) setups and not
     * requested at all for the rest.
     */
    protected function residentKey(bool $discoverable): string|false
    {
        $value = strtolower(trim((string) config('golem15.user::webAuthnResidentKey', '')));
        if (in_array($value, ['required', 'preferred', 'discouraged'], true)) {
            return $value;
        }

        return $discoverable ? 'preferred' : false;
    }
}
