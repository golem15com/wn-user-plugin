<?php namespace Golem15\User\Tests\Security;

use Golem15\User\Models\User;
use Golem15\User\Tests\UserPluginTestCase;
use Mockery;

/**
 * Security PoC tests for CRITICAL findings USER-001.
 * Each test method is named test_user_NNN_<short_slug> and references the finding ID
 * in .planning/audit/plugins/user/FINDINGS.md.
 *
 * @group security
 *
 * Per Phase 3 D-20: these tests MUST FAIL on current code (red-bar regression locks).
 * Phase 7 / RMED-01 remediation will turn them green.
 */
class DataHandlingTest extends UserPluginTestCase
{
    public function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    /**
     * USER-001: OAuth tokens should NOT be mass-assignable via $fillable.
     *
     * The User model's $fillable array includes oauth_access_token, oauth_refresh_token,
     * oauth_provider, oauth_provider_id, and related OAuth fields. These fields should
     * only be set programmatically via linkOAuthProvider() which handles encryption and
     * validation — never via user-controlled mass-assignment (register, update, fill).
     *
     * EXPECTATION (post-fix Phase 7): fill() silently ignores OAuth fields because they
     * have been removed from $fillable. The oauth_access_token attribute remains null.
     *
     * TODAY (pre-fix Phase 3): fill() accepts OAuth fields because they ARE in $fillable.
     * The assertion fails because oauth_access_token is set to the attacker's plaintext
     * value — this is the red-bar lock proving the vulnerability exists.
     *
     * @test
     * @group security
     * @see .planning/audit/plugins/user/FINDINGS.md USER-001
     */
    public function test_user_001_oauth_tokens_mass_assignable(): void
    {
        // Arrange: create a partial mock of User to avoid database writes
        $user = Mockery::mock(User::class)->makePartial();
        $user->shouldReceive('flushEventListeners')->andReturnNull();

        // Act: simulate what Auth::register($request->all()) does when an attacker
        // includes OAuth fields in the registration POST body
        $user->fill([
            'name'               => 'Legitimate User',
            'email'              => 'victim@example.tld',
            'password'           => 'StrongP@ssw0rd!',
            'oauth_access_token' => 'ATTACKER_PLAINTEXT_TOKEN',
            'oauth_provider'     => 'google',
            'oauth_provider_id'  => 'ATTACKER_GOOGLE_ID_12345',
        ]);

        // EXPECTATION (post-fix Phase 7): OAuth fields are NOT in $fillable, so fill()
        // silently ignores them. The attribute remains null.
        // TODAY (pre-fix Phase 3): OAuth fields ARE in $fillable, so fill() sets them.
        // This assertion FAILS because oauth_access_token is 'ATTACKER_PLAINTEXT_TOKEN'.
        $this->assertNull(
            $user->oauth_access_token,
            'USER-001: OAuth access token was mass-assigned via fill(). '
            . 'The oauth_access_token field should NOT be in $fillable — it should only '
            . 'be set via linkOAuthProvider() which encrypts the value. '
            . 'Post-fix: remove OAuth fields from $fillable.'
        );
    }
}
