<?php

namespace Golem15\User\Tests\Unit\TwoFactor;

/**
 * A PHP software authenticator for browserless WebAuthn tests.
 *
 * Holds one EC P-256 (ES256) credential and produces the same byte layouts a
 * browser hands to the server:
 *   - create(): clientDataJSON + a "none" attestationObject whose authData carries
 *     the attested credential data and a COSE EC2 public key;
 *   - get(): clientDataJSON + authenticatorData + a DER ECDSA signature over
 *     authData || sha256(clientDataJSON).
 * All binary values are returned standard-base64 encoded, which is what
 * WebAuthnMethod base64_decode()s. Not a TestCase (PHPUnit only collects
 * *Test.php); loaded with require_once from TwoFactorTestCase.
 */
class SoftAuthenticator
{
    private const FLAG_UP = 0x01;
    private const FLAG_UV = 0x04;
    private const FLAG_AT = 0x40;

    /** @var \OpenSSLAsymmetricKey */
    private $key;

    private string $credentialId;

    public function __construct(private string $rpId, private string $origin)
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        if ($key === false) {
            throw new \RuntimeException('SoftAuthenticator: could not generate a P-256 key');
        }

        $this->key = $key;
        $this->credentialId = random_bytes(16);
    }

    public function credentialIdB64(): string
    {
        return base64_encode($this->credentialId);
    }

    public function credentialIdBin(): string
    {
        return $this->credentialId;
    }

    /**
     * @return array{clientDataJSON: string, attestationObject: string, rawId: string}
     */
    public function create(string $challengeBin, bool $uv = true): array
    {
        $clientDataJSON = $this->clientData('webauthn.create', $challengeBin);

        $details = openssl_pkey_get_details($this->key);
        $x = str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT);
        $y = str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);

        // COSE_Key: {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
        $coseKey = self::map([
            [self::int(1), self::int(2)],
            [self::int(3), self::int(-7)],
            [self::int(-1), self::int(1)],
            [self::int(-2), self::bytes($x)],
            [self::int(-3), self::bytes($y)],
        ]);

        $flags = self::FLAG_UP | self::FLAG_AT | ($uv ? self::FLAG_UV : 0);
        $authData = hash('sha256', $this->rpId, true)
            . chr($flags)
            . pack('N', 0)
            . str_repeat("\0", 16)
            . pack('n', strlen($this->credentialId))
            . $this->credentialId
            . $coseKey;

        $attestationObject = self::map([
            [self::text('fmt'), self::text('none')],
            [self::text('attStmt'), self::map([])],
            [self::text('authData'), self::bytes($authData)],
        ]);

        return [
            'clientDataJSON' => base64_encode($clientDataJSON),
            'attestationObject' => base64_encode($attestationObject),
            'rawId' => base64_encode($this->credentialId),
        ];
    }

    /**
     * @return array{id: string, rawId: string, response: array<string, string>}
     */
    public function get(string $challengeBin, bool $uv = true, ?string $userHandleBin = null, int $signCount = 1): array
    {
        $clientDataJSON = $this->clientData('webauthn.get', $challengeBin);

        $flags = self::FLAG_UP | ($uv ? self::FLAG_UV : 0);
        $authData = hash('sha256', $this->rpId, true) . chr($flags) . pack('N', $signCount);

        $signature = '';
        if (!openssl_sign($authData . hash('sha256', $clientDataJSON, true), $signature, $this->key, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('SoftAuthenticator: signing failed');
        }

        $response = [
            'clientDataJSON' => base64_encode($clientDataJSON),
            'authenticatorData' => base64_encode($authData),
            'signature' => base64_encode($signature),
        ];
        if ($userHandleBin !== null) {
            $response['userHandle'] = base64_encode($userHandleBin);
        }

        return [
            'id' => base64_encode($this->credentialId),
            'rawId' => base64_encode($this->credentialId),
            'response' => $response,
        ];
    }

    private function clientData(string $type, string $challengeBin): string
    {
        return json_encode([
            'type' => $type,
            'challenge' => rtrim(strtr(base64_encode($challengeBin), '+/', '-_'), '='),
            'origin' => $this->origin,
            'crossOrigin' => false,
        ], JSON_UNESCAPED_SLASHES);
    }

    // ------------------------------------------------------------------
    // Minimal CBOR encoder (RFC 8949): ints, byte/text strings, maps.
    // ------------------------------------------------------------------

    private static function head(int $major, int $length): string
    {
        $m = $major << 5;
        if ($length < 24) {
            return chr($m | $length);
        }
        if ($length < 0x100) {
            return chr($m | 24) . chr($length);
        }
        if ($length < 0x10000) {
            return chr($m | 25) . pack('n', $length);
        }

        return chr($m | 26) . pack('N', $length);
    }

    private static function int(int $value): string
    {
        return $value >= 0 ? self::head(0, $value) : self::head(1, -1 - $value);
    }

    private static function bytes(string $value): string
    {
        return self::head(2, strlen($value)) . $value;
    }

    private static function text(string $value): string
    {
        return self::head(3, strlen($value)) . $value;
    }

    /**
     * @param array<int, array{0: string, 1: string}> $pairs pre-encoded [key, value] pairs
     */
    private static function map(array $pairs): string
    {
        $out = self::head(5, count($pairs));
        foreach ($pairs as [$k, $v]) {
            $out .= $k . $v;
        }

        return $out;
    }
}
