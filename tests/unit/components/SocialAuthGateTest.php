<?php

namespace Golem15\User\Tests\Unit\Components;

use ReflectionMethod;
use Laravel\Socialite\Two\User as SocialiteTwoUser;
use Laravel\Socialite\Contracts\User as SocialiteUser;
use Golem15\User\Components\SocialAuth;
use Golem15\User\Tests\UserPluginTestCase;

/**
 * Phase 26-01 D-06/D-07 auto-link gate + reason discriminator coverage.
 *
 * Asserts:
 *  - providerEmailVerified() gate: facebook => always false; google reads $raw['email_verified'].
 *  - redirectToPendingRegistration() appends the EXACT cross-plan reason literals
 *    (`reason=unverified_match`, `reason=fb_no_email`) when a reason is threaded, and NO reason
 *    param when none is passed (the genuine new-OAuth-user path).
 *
 * The reason literals are a byte-for-byte contract with Plan 04's OAuthRegisterView.
 *
 * @group registration
 */
class SocialAuthGateTest extends UserPluginTestCase
{
    /**
     * Build a CONCRETE Socialite user (Two\User extends AbstractUser) so getRaw() is a real
     * method — matching runtime fidelity. The Contracts\User interface does NOT declare getRaw(),
     * so a bare interface mock would make providerEmailVerified()'s method_exists() guard return
     * false and never read the email_verified claim.
     */
    protected function socialiteUser(?string $email, array $raw = [], string $id = 'provider-id-123'): SocialiteUser
    {
        $user = new SocialiteTwoUser();
        $user->map([
            'id' => $id,
            'name' => 'Social Tester',
            'email' => $email,
            'avatar' => null,
        ]);
        $user->setRaw($raw);
        $user->setToken('tok')->setRefreshToken('refresh')->setExpiresIn(3600);

        return $user;
    }

    protected function invokeProtected(SocialAuth $component, string $method, array $args)
    {
        $ref = new ReflectionMethod(SocialAuth::class, $method);
        $ref->setAccessible(true);

        return $ref->invokeArgs($component, $args);
    }

    //
    // providerEmailVerified() gate (D-06 / D-07)
    //

    public function test_google_verified_email_passes_gate(): void
    {
        $component = new SocialAuth();
        $verified = $this->invokeProtected($component, 'providerEmailVerified', [
            'google',
            $this->socialiteUser('user@gmail.com', ['email_verified' => true]),
        ]);

        $this->assertTrue($verified);
    }

    public function test_google_unverified_email_fails_gate(): void
    {
        $component = new SocialAuth();
        $verified = $this->invokeProtected($component, 'providerEmailVerified', [
            'google',
            $this->socialiteUser('user@gmail.com', ['email_verified' => false]),
        ]);

        $this->assertFalse($verified);
    }

    public function test_facebook_always_fails_gate(): void
    {
        $component = new SocialAuth();
        $verified = $this->invokeProtected($component, 'providerEmailVerified', [
            'facebook',
            $this->socialiteUser('user@facebook.com', ['email_verified' => true]),
        ]);

        $this->assertFalse($verified);
    }

    //
    // redirectToPendingRegistration() reason discriminator (Plan 01 <-> Plan 04 contract)
    //

    public function test_divert_appends_unverified_match_reason(): void
    {
        session(['oauth_context' => [
            'mode' => 'spa',
            'frontend_callback' => 'https://app.example.tld/auth/oauth/callback',
            'return_to' => '/',
        ]]);

        $component = new SocialAuth();
        $redirect = $this->invokeProtected($component, 'redirectToPendingRegistration', [
            'google',
            $this->socialiteUser('match@example.tld', ['email_verified' => false]),
            'unverified_match',
        ]);

        $url = $redirect->getTargetUrl();
        $this->assertStringContainsString('pending_registration=', $url);
        $this->assertStringContainsString('reason=unverified_match', $url);
        // WR-03: provider + email additively threaded for the frontend consent/confirm screen.
        $this->assertStringContainsString('provider=google', $url);
        $this->assertStringContainsString('email=' . urlencode('match@example.tld'), $url);
    }

    public function test_divert_appends_fb_no_email_reason(): void
    {
        session(['oauth_context' => [
            'mode' => 'spa',
            'frontend_callback' => 'https://app.example.tld/auth/oauth/callback',
            'return_to' => '/',
        ]]);

        $component = new SocialAuth();
        $redirect = $this->invokeProtected($component, 'redirectToPendingRegistration', [
            'facebook',
            $this->socialiteUser(null, []),
            'fb_no_email',
        ]);

        $url = $redirect->getTargetUrl();
        $this->assertStringContainsString('pending_registration=', $url);
        $this->assertStringContainsString('reason=fb_no_email', $url);
        // WR-03: provider is always threaded; email is omitted when the social user has none.
        $this->assertStringContainsString('provider=facebook', $url);
        $this->assertStringNotContainsString('email=', $url);
    }

    public function test_divert_without_reason_emits_no_reason_param(): void
    {
        session(['oauth_context' => [
            'mode' => 'spa',
            'frontend_callback' => 'https://app.example.tld/auth/oauth/callback',
            'return_to' => '/',
        ]]);

        $component = new SocialAuth();
        $redirect = $this->invokeProtected($component, 'redirectToPendingRegistration', [
            'google',
            $this->socialiteUser('new@example.tld', ['email_verified' => true]),
        ]);

        $url = $redirect->getTargetUrl();
        $this->assertStringContainsString('pending_registration=', $url);
        $this->assertStringNotContainsString('reason=', $url);
        // WR-03: provider + email still threaded on the genuine new-user (no-reason) path.
        $this->assertStringContainsString('provider=google', $url);
        $this->assertStringContainsString('email=' . urlencode('new@example.tld'), $url);
    }

    //
    // GitHub gate verdict
    //

    public function test_github_passes_gate(): void
    {
        $component = new SocialAuth();
        $verified = $this->invokeProtected($component, 'providerEmailVerified', [
            'github',
            // GitHub exposes no email_verified claim at all — Socialite guarantees the address
            // is the primary AND verified one before it reaches us.
            $this->socialiteUser('user@github.tld', []),
        ]);

        $this->assertTrue($verified);
    }

    //
    // The pending payload must carry the gate verdict, or completePendingRegistration()
    // cannot distinguish a verified match from an unverified one.
    //

    protected function cachedPendingPayload($redirect): array
    {
        parse_str((string) parse_url($redirect->getTargetUrl(), PHP_URL_QUERY), $query);
        $this->assertArrayHasKey('pending_registration', $query);

        $payload = \Cache::get('oauth-pending-registration:' . $query['pending_registration']);
        $this->assertIsArray($payload);

        return $payload;
    }

    public function test_pending_payload_records_unverified_provider(): void
    {
        session(['oauth_context' => [
            'mode' => 'spa',
            'frontend_callback' => 'https://app.example.tld/auth/oauth/callback',
            'return_to' => '/',
        ]]);

        $component = new SocialAuth();
        $payload = $this->cachedPendingPayload($this->invokeProtected($component, 'redirectToPendingRegistration', [
            'facebook',
            $this->socialiteUser('victim@example.tld', []),
            'unverified_match',
        ]));

        $this->assertArrayHasKey('email_verified', $payload);
        $this->assertFalse($payload['email_verified']);
        $this->assertSame('unverified_match', $payload['reason']);
    }

    public function test_pending_payload_records_verified_provider(): void
    {
        session(['oauth_context' => [
            'mode' => 'spa',
            'frontend_callback' => 'https://app.example.tld/auth/oauth/callback',
            'return_to' => '/',
        ]]);

        $component = new SocialAuth();
        $payload = $this->cachedPendingPayload($this->invokeProtected($component, 'redirectToPendingRegistration', [
            'google',
            $this->socialiteUser('new@example.tld', ['email_verified' => true]),
        ]));

        $this->assertTrue($payload['email_verified']);
        $this->assertNull($payload['reason']);
    }

    //
    // Web-mode (no frontend_callback) divert must not recurse.
    //
    // Before the fix, a reasoned divert with no frontend_callback fell through to
    // handleOAuthRegistration(), which re-triggered the very same divert and landed back here —
    // unbounded recursion until the stack was exhausted (fatal, not a catchable exception).
    //

    public function test_web_mode_unverified_match_divert_does_not_recurse(): void
    {
        session()->forget('oauth_context');

        $component = new SocialAuth();
        $redirect = $this->invokeProtected($component, 'redirectToPendingRegistration', [
            'facebook',
            $this->socialiteUser('victim@example.tld', []),
            'unverified_match',
        ]);

        $this->assertStringContainsString('/login', $redirect->getTargetUrl());
    }

    public function test_web_mode_missing_email_divert_does_not_recurse(): void
    {
        session()->forget('oauth_context');

        $component = new SocialAuth();
        $redirect = $this->invokeProtected($component, 'redirectToPendingRegistration', [
            'facebook',
            $this->socialiteUser(null, []),
            'fb_no_email',
        ]);

        $this->assertStringContainsString('/login', $redirect->getTargetUrl());
    }
}
