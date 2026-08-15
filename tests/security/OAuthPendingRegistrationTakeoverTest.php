<?php namespace Golem15\User\Tests\Security;

use ApplicationException;
use Golem15\User\Components\SocialAuth;
use Golem15\User\Models\User as UserModel;
use Golem15\User\Tests\UserPluginTestCase;

/**
 * Regression lock: account takeover through the OAuth pending-registration screen.
 *
 * The D-06 gate (providerEmailVerified()) refuses to auto-link an existing-email match when the
 * provider does not assert the address is verified — Facebook always, and GitHub used to as well.
 * It diverts the caller to the "finish registration" screen with reason=unverified_match.
 *
 * completePendingRegistration() then looked that account up BY EMAIL and logged into it with no
 * ownership proof whatsoever, so the mitigation redirected straight into its own bypass:
 *
 *   Facebook account carrying a victim's email  ->  accept the two consent checkboxes
 *   ->  full JWT session on the victim's account.
 *
 * Reachable unauthenticated in production via POST /_user/api/v1/oauth-register-complete, which
 * carries only ['throttle:user-api', 'bindings'] — no jwt.auth.
 *
 * These tests must fail if the guard in completePendingRegistration() is ever removed.
 *
 * @group security
 * @group registration
 */
class OAuthPendingRegistrationTakeoverTest extends UserPluginTestCase
{
    protected function makeVictim(array $overrides = []): UserModel
    {
        $user = new UserModel();
        $user->fill(array_merge([
            'name' => 'Victim',
            'email' => 'victim@example.tld',
            'password' => 'victimpass123',
            'password_confirmation' => 'victimpass123',
        ], $overrides));
        $user->is_activated = true;
        $user->forceSave();

        return $user;
    }

    /**
     * The shape redirectToPendingRegistration() caches, as completePendingRegistration() sees it.
     */
    protected function pendingPayload(array $overrides = []): array
    {
        return array_merge([
            'provider' => 'facebook',
            'provider_id' => 'attacker-fb-id-999',
            'token' => 'tok',
            'refresh_token' => 'refresh',
            'expires_in' => 3600,
            'name' => 'Attacker',
            'email' => 'victim@example.tld',
            'avatar' => null,
            'return_to' => '/',
            'email_verified' => false,
            'reason' => 'unverified_match',
            'terms_accepted' => true,
            'privacy_accepted' => true,
            'marketing_consent' => false,
        ], $overrides);
    }

    /**
     * The exploit itself.
     */
    public function test_unverified_provider_email_cannot_hijack_existing_account(): void
    {
        $victim = $this->makeVictim();

        $this->expectException(ApplicationException::class);

        try {
            (new SocialAuth())->completePendingRegistration($this->pendingPayload());
        } finally {
            // No provider link may be grafted onto the victim, and no second account may be
            // silently created under the victim's address.
            $victim = $victim->fresh();
            $this->assertFalse(
                (bool) $victim->hasOAuthProvider('facebook'),
                'Unverified Facebook identity was linked to the victim account.'
            );
            $this->assertSame(
                1,
                UserModel::where('email', 'victim@example.tld')->count(),
                'Blocked takeover must not fork a duplicate account on the victim address.'
            );
        }
    }

    /**
     * A payload cached before this fix shipped has no email_verified key at all — fail closed
     * rather than treating the absent key as permission.
     */
    public function test_payload_without_verification_flag_is_rejected(): void
    {
        $this->makeVictim();

        $payload = $this->pendingPayload();
        unset($payload['email_verified']);

        $this->expectException(ApplicationException::class);
        (new SocialAuth())->completePendingRegistration($payload);
    }

    /**
     * Non-breaking guarantee: a provider-verified match still auto-links in one click.
     */
    public function test_verified_provider_email_still_auto_links(): void
    {
        $existing = $this->makeVictim(['email' => 'verified@example.tld']);

        $result = (new SocialAuth())->completePendingRegistration($this->pendingPayload([
            'provider' => 'google',
            'provider_id' => 'google-id-123',
            'email' => 'verified@example.tld',
            'email_verified' => true,
            'reason' => null,
        ]));

        $this->assertSame('login', $result['action']);
        $this->assertNotEmpty($result['token']);
        $this->assertSame($existing->id, $result['user']['id']);
    }

    /**
     * Non-breaking guarantee: a genuine new user is unaffected by the guard.
     */
    public function test_new_user_registration_is_unaffected(): void
    {
        $result = (new SocialAuth())->completePendingRegistration($this->pendingPayload([
            'name' => 'Brand New',
            'email' => 'brand-new@example.tld',
            'email_verified' => false,
            'reason' => null,
        ]));

        $this->assertSame('register', $result['action']);
        $this->assertNotEmpty($result['token']);
        $this->assertNotNull(UserModel::where('email', 'brand-new@example.tld')->first());
    }

    /**
     * Non-breaking guarantee: an already-linked provider identity is proof of ownership and
     * short-circuits before the email branch, verified flag or not.
     */
    public function test_already_linked_provider_identity_still_logs_in(): void
    {
        $user = $this->makeVictim(['email' => 'linked@example.tld']);
        $user->linkOAuthProvider('facebook', 'known-fb-id-42', ['token' => 'tok'], []);

        $result = (new SocialAuth())->completePendingRegistration($this->pendingPayload([
            'provider_id' => 'known-fb-id-42',
            'email' => 'linked@example.tld',
        ]));

        $this->assertSame('login', $result['action']);
        $this->assertSame($user->id, $result['user']['id']);
    }
}
