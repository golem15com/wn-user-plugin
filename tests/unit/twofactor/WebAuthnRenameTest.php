<?php

namespace Golem15\User\Tests\Unit\TwoFactor;

require_once __DIR__ . '/TwoFactorTestCase.php';

use Golem15\User\Controllers\TwoFactorApiController;
use Golem15\User\Models\WebAuthnCredential;

/**
 * D-23: PATCH /2fa/webauthn/{id} {name} renames only the caller's own
 * credential; status lists name, created_at and last_used_at.
 */
class WebAuthnRenameTest extends TwoFactorTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        $this->enableTwoFactorSettings();
        $this->configureWebAuthn();
    }

    private function rename($user, int $id, $name): array
    {
        $jwt = $this->jwtFor($user);
        $body = $name === null ? [] : ['name' => $name];

        return $this->callJson(fn () => (new TwoFactorApiController())->webauthnRename($this->request($body, $jwt, 'PATCH'), $id));
    }

    public function test_rename_sets_the_trimmed_name(): void
    {
        $user = $this->makeUser();
        $credential = $this->registerSoftKey($user, $this->softAuthenticator(), true, 'Old name');

        [$status, $body] = $this->rename($user, $credential->id, '  Desk key  ');

        $this->assertSame(200, $status, json_encode($body));
        $this->assertSame('Security key renamed.', $body['message']);
        $this->assertSame('Desk key', WebAuthnCredential::find($credential->id)->name);
        $this->assertSame('Desk key', $body['status']['webauthn_credentials'][0]['name']);
    }

    public function test_rename_of_another_users_credential_is_404(): void
    {
        $owner = $this->makeUser();
        $credential = $this->registerSoftKey($owner, $this->softAuthenticator(), true, 'Owner key');
        $intruder = $this->makeUser();

        [$status, $body] = $this->rename($intruder, $credential->id, 'Mine now');

        $this->assertSame(404, $status);
        $this->assertSame('Credential not found.', $body['error']);
        $this->assertSame('Owner key', WebAuthnCredential::find($credential->id)->name);
    }

    public function test_rename_rejects_a_name_over_64_characters(): void
    {
        $user = $this->makeUser();
        $credential = $this->registerSoftKey($user, $this->softAuthenticator());

        [$status, $body] = $this->rename($user, $credential->id, str_repeat('a', 65));

        $this->assertSame(422, $status);
        $this->assertArrayHasKey('errors', $body);
    }

    public function test_rename_rejects_a_whitespace_only_or_missing_name(): void
    {
        $user = $this->makeUser();
        $credential = $this->registerSoftKey($user, $this->softAuthenticator());

        [$status] = $this->rename($user, $credential->id, '   ');
        $this->assertSame(422, $status);

        [$status] = $this->rename($user, $credential->id, null);
        $this->assertSame(422, $status);
    }

    public function test_rename_accepts_exactly_64_characters(): void
    {
        $user = $this->makeUser();
        $credential = $this->registerSoftKey($user, $this->softAuthenticator());

        [$status] = $this->rename($user, $credential->id, str_repeat('b', 64));

        $this->assertSame(200, $status);
    }

    public function test_rename_without_a_token_is_401(): void
    {
        [$status] = $this->callJson(fn () => (new TwoFactorApiController())->webauthnRename($this->request(['name' => 'x'], null, 'PATCH'), 1));

        $this->assertSame(401, $status);
    }

    public function test_status_lists_name_created_at_and_last_used_at(): void
    {
        $user = $this->makeUser();
        $this->registerSoftKey($user, $this->softAuthenticator(), true, 'Desk key');

        $credential = $this->service()->getStatus($user)['webauthn_credentials'][0];

        $this->assertSame('Desk key', $credential['name']);
        $this->assertArrayHasKey('created_at', $credential);
        $this->assertArrayHasKey('last_used_at', $credential);
        $this->assertNotNull($credential['created_at']);
    }
}
