<?php namespace Golem15\User\Tests\Security;

use ApplicationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Mail;
use Mockery;
use Golem15\User\Components\SocialAuth;
use Golem15\User\Controllers\ApiController;
use Golem15\User\Models\User as UserModel;
use Golem15\User\Tests\UserPluginTestCase;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

/**
 * k7ut351s — an account created through Google/Facebook OAuth registration has
 * `password` filled with Str::random(16) at registration time
 * (SocialAuth.php ~527 / ~1033), so ApiController::changePassword()'s
 * Hash::check() against that placeholder hash can never pass: the account has
 * NO route to a self-chosen password anywhere in the product. The same root
 * cause left the "prevent lockout" guard in SocialAuth::onUnlinkOAuth() dead —
 * it tested empty($user->password), which is never true for an OAuth account,
 * so unlinking the last identity from a password-less account was silently
 * allowed and would strand the holder with no way to sign back in.
 *
 * These tests lock BOTH halves of the fix (14-01-PLAN.md Task 2):
 *  1. An account with has_self_set_password === false may change its password
 *     WITHOUT current_password -- but ONLY after confirming a short-lived,
 *     single-use code emailed to its own address (CR-01, 14-REVIEW.md; see
 *     below).
 *  2. An account with a real, self-set password is BYTE-IDENTICAL to today:
 *     current_password is still required and still checked (proof: 422s, not
 *     a declaration).
 *  3. The unlink guard actually fires for a password-less account unlinking
 *     its LAST identity, and does not fire for the safe cases (a non-last
 *     identity on the same account, or any identity on a real-password
 *     account).
 *  4. The relaxation is one-shot: the first successful password write disarms
 *     the flag, closing the window.
 *  5. OAuth registration marks brand-new accounts has_self_set_password=false
 *     from the first second they exist (does not rely solely on the v3.4.0
 *     migration backfill).
 *
 * CR-01 / WR-01 (code review of the above, 14-REVIEW.md): the tests below
 * marked "CR-01" / "WR-01" close the two gaps that review found:
 *  - CR-01 (critical): a bearer JWT alone was sufficient to complete #1 above,
 *    turning any stolen token for this cohort into a permanent password
 *    takeover. Fixed by requiring a short-lived, single-use confirmation code
 *    emailed to the account's own registered address before the write commits
 *    (User::issuePasswordBootstrapCode()/verifyPasswordBootstrapCode()).
 *  - WR-01 (warning): SocialAuth::onUnlinkOAuth()'s lockout guard was
 *    check-then-act (read count(), then delete) with no atomicity, so two
 *    concurrent unlinks on a 2-identity password-less account could both pass
 *    and strip every identity. Fixed by folding the guard into a single
 *    atomic DELETE statement (User::unlinkOAuthProviderIfSafe()).
 *
 * @group security
 */
class OAuthPasswordBootstrapTest extends UserPluginTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        if (!Config::get('jwt.secret')) {
            Config::set('jwt.secret', 'testing-only-deterministic-jwt-secret-key-0001');
        }
        Config::set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'users']);
        Config::set('auth.providers.users', ['driver' => 'eloquent', 'model' => UserModel::class]);
    }

    /**
     * @param array $overrides
     * @param bool  $hasSelfSetPassword Written the same way the production code paths write
     *                                  it: direct property assignment, never through $fillable
     *                                  (see User::$fillable / User::$casts, Task 1).
     */
    protected function makeUser(array $overrides, bool $hasSelfSetPassword): UserModel
    {
        $user = new UserModel();
        $user->fill(array_merge([
            'name' => 'Bootstrap Tester',
            'email' => 'bootstrap-' . uniqid() . '@example.tld',
            'password' => 'placeholder-not-asserted-1',
            'password_confirmation' => 'placeholder-not-asserted-1',
        ], $overrides));
        $user->is_activated = true;
        $user->has_self_set_password = $hasSelfSetPassword;
        $user->forceSave();

        return $user->fresh();
    }

    protected function linkOAuth(UserModel $user, string $provider = 'google', ?string $providerId = null): void
    {
        $user->linkOAuthProvider($provider, $providerId ?? ('id-' . uniqid()), ['token' => 'tok'], []);
    }

    /**
     * Bind $user as the authenticated caller of the current request container.
     * Both JWT-guard paths this file exercises read from here:
     * ApiController::authorize() via TokenExtractor::fromRequest($request), and
     * SocialAuth::resolveAuthenticatedUser() via JWTAuth::parseToken() against
     * the bound container request.
     */
    protected function authedRequest(UserModel $user, array $data = []): Request
    {
        $this->app->forgetInstance('tymon.jwt');
        $this->app->forgetInstance('tymon.jwt.parser');

        $request = Request::create('/_user/api/v1/change-password', 'POST', $data);
        $request->headers->set('Authorization', 'Bearer ' . JWTAuth::fromUser($user));

        $this->app->instance('request', $request);
        // The Request facade caches its first-resolved instance; without clearing
        // it here, SocialAuth's post('provider') keeps reading the stale GET
        // request from bootstrap instead of this test's rebound POST request.
        \Illuminate\Support\Facades\Request::clearResolvedInstance('request');
        JWTAuth::setRequest($request);

        return $request;
    }

    protected function unlinkAs(UserModel $user, string $provider): array
    {
        $this->authedRequest($user, ['provider' => $provider]);

        return (new SocialAuth())->onUnlinkOAuth();
    }

    /**
     * Swap the Mail facade root with a Mockery spy (same pattern as
     * PasswordResetActivateTest::spyMail() — MailFake silently drops the raw-view
     * `Mail::queue($view, $data, $closure)` calls this plugin uses, so a spy on the
     * underlying mailer is used instead of Mail::fake()).
     */
    protected function spyMail()
    {
        $spy = Mockery::spy('Illuminate\Contracts\Mail\Mailer');
        Mail::swap($spy);

        return $spy;
    }

    protected function pendingPayload(array $overrides = []): array
    {
        return array_merge([
            'provider' => 'google',
            'provider_id' => 'new-oauth-id-' . uniqid(),
            'token' => 'tok',
            'refresh_token' => 'refresh',
            'expires_in' => 3600,
            'name' => 'Brand New OAuth User',
            'email' => 'new-oauth-' . uniqid() . '@example.tld',
            'avatar' => null,
            'return_to' => '/',
            'email_verified' => true,
            'reason' => null,
            'terms_accepted' => true,
            'privacy_accepted' => true,
            'marketing_consent' => false,
        ], $overrides);
    }

    // 1. Half one of k7ut351s: OAuth account sets a password without current_password
    //    — but ONLY after confirming the emailed code (CR-01, 14-REVIEW.md). This is
    //    the k7ut351s regression guard: the legitimate owner must still be able to
    //    finish the flow, never being sent back to "current password required".

    public function test_oauth_account_sets_password_without_current_password(): void
    {
        $user = $this->makeUser(['email' => 'oauth-half1@example.tld'], false);
        $this->linkOAuth($user, 'google');

        $mail = $this->spyMail();

        // Step 1: no confirmation code yet -> the write must NOT happen; a code is
        // emailed instead.
        $first = (new ApiController())->changePassword($this->authedRequest($user, [
            'password' => 'BrandNewSecret1',
            'password_confirmation' => 'BrandNewSecret1',
        ]));
        $this->assertSame(428, $first->getStatusCode());
        $this->assertTrue($first->getData(true)['requires_confirmation']);

        $user = $user->fresh();
        $this->assertTrue(
            Hash::check('placeholder-not-asserted-1', $user->password),
            'The password must not change before the confirmation code is verified.'
        );

        $capturedCode = null;
        $mail->shouldHaveReceived('queue')
            ->with(
                'golem15.user::mail.password_bootstrap_code',
                Mockery::on(function ($data) use (&$capturedCode) {
                    $capturedCode = $data['code'] ?? null;
                    return true;
                }),
                Mockery::type('callable')
            )
            ->once();
        $this->assertNotNull($capturedCode, 'A confirmation code must have been emailed to the account.');

        // Step 2: the legitimate owner retrieves the code from their OWN mailbox
        // (something a stolen bearer token does not grant — see the CR-01 tests
        // below) and resubmits it. k7ut351s stays fixed: still no "current password".
        $second = (new ApiController())->changePassword($this->authedRequest($user, [
            'password' => 'BrandNewSecret1',
            'password_confirmation' => 'BrandNewSecret1',
            'password_bootstrap_code' => $capturedCode,
        ]));
        $this->assertSame(200, $second->getStatusCode());

        $user = $user->fresh();
        $this->assertTrue(Hash::check('BrandNewSecret1', $user->password));
        $this->assertTrue((bool) $user->has_self_set_password);
    }

    // 2. Dowód neutralności: a real-password account is byte-identical to today.

    public function test_real_password_account_still_requires_current_password(): void
    {
        $user = $this->makeUser([
            'email' => 'real-neutral@example.tld',
            'password' => 'OriginalSecret1',
            'password_confirmation' => 'OriginalSecret1',
        ], true);

        $missing = (new ApiController())->changePassword($this->authedRequest($user, [
            'password' => 'NewSecret2',
            'password_confirmation' => 'NewSecret2',
        ]));
        $this->assertSame(422, $missing->getStatusCode(), 'A real-password account must still require current_password.');

        $wrong = (new ApiController())->changePassword($this->authedRequest($user, [
            'current_password' => 'DefinitelyWrong',
            'password' => 'NewSecret2',
            'password_confirmation' => 'NewSecret2',
        ]));
        $this->assertSame(422, $wrong->getStatusCode());
        $this->assertSame(
            Lang::get('golem15.user::lang.account.invalid_login'),
            $wrong->getData(true)['error'],
            'The wrong-current-password error message must be unchanged.'
        );

        $user = $user->fresh();
        $this->assertTrue(Hash::check('OriginalSecret1', $user->password), 'Password must not have changed.');
    }

    // 3. The dead guard is alive — and only where it should be.

    public function test_unlink_guard_blocks_last_identity_on_password_less_account(): void
    {
        $user = $this->makeUser(['email' => 'oauth-guard@example.tld'], false);
        $this->linkOAuth($user, 'google', 'guard-single-1');

        $this->expectException(ApplicationException::class);
        // Pin the exact message, not just the exception class — a request-plumbing
        // bug that made hasOAuthProvider() see no linked provider at all would also
        // throw ApplicationException (the "no_provider_linked" branch, one line
        // above the real guard) and falsely look like a passing test.
        $this->expectExceptionMessage(Lang::get('golem15.user::lang.oauth.cannot_unlink_without_password'));

        try {
            $this->unlinkAs($user, 'google');
        } finally {
            $this->assertTrue(
                $user->fresh()->hasOAuthProvider('google'),
                'Last OAuth identity on a password-less account must survive a blocked unlink attempt.'
            );
        }
    }

    public function test_unlink_guard_allows_non_last_identity_on_password_less_account(): void
    {
        $user = $this->makeUser(['email' => 'oauth-guard-multi@example.tld'], false);
        $this->linkOAuth($user, 'google', 'guard-multi-google');
        $this->linkOAuth($user, 'facebook', 'guard-multi-facebook');

        $result = $this->unlinkAs($user, 'google');

        $this->assertSame(['success' => true], $result);
        $user = $user->fresh();
        $this->assertFalse($user->hasOAuthProvider('google'));
        $this->assertTrue($user->hasOAuthProvider('facebook'));
        $this->assertSame(1, $user->oauthIdentities()->count());
    }

    public function test_unlink_guard_allows_last_identity_on_real_password_account(): void
    {
        $user = $this->makeUser([
            'email' => 'real-guard@example.tld',
            'password' => 'RealSecret999',
            'password_confirmation' => 'RealSecret999',
        ], true);
        $this->linkOAuth($user, 'google', 'guard-real-google');

        $result = $this->unlinkAs($user, 'google');

        $this->assertSame(['success' => true], $result);
        $this->assertSame(0, $user->fresh()->oauthIdentities()->count());
    }

    // 4. Disarm: the relaxation window is one-shot.

    public function test_disarm_closes_the_no_current_password_window(): void
    {
        $user = $this->makeUser(['email' => 'oauth-disarm@example.tld'], false);
        $this->linkOAuth($user, 'google', 'disarm-1');

        $mail = $this->spyMail();

        $issue = (new ApiController())->changePassword($this->authedRequest($user, [
            'password' => 'FirstSecret1',
            'password_confirmation' => 'FirstSecret1',
        ]));
        $this->assertSame(428, $issue->getStatusCode());

        $capturedCode = null;
        $mail->shouldHaveReceived('queue')
            ->with(
                'golem15.user::mail.password_bootstrap_code',
                Mockery::on(function ($data) use (&$capturedCode) {
                    $capturedCode = $data['code'] ?? null;
                    return true;
                }),
                Mockery::type('callable')
            )
            ->once();

        $first = (new ApiController())->changePassword($this->authedRequest($user, [
            'password' => 'FirstSecret1',
            'password_confirmation' => 'FirstSecret1',
            'password_bootstrap_code' => $capturedCode,
        ]));
        $this->assertSame(200, $first->getStatusCode());

        $user = $user->fresh();
        $this->assertTrue((bool) $user->has_self_set_password, 'A successful write must disarm the flag.');

        $second = (new ApiController())->changePassword($this->authedRequest($user, [
            'password' => 'SecondSecret2',
            'password_confirmation' => 'SecondSecret2',
        ]));
        $this->assertSame(
            422,
            $second->getStatusCode(),
            'The relaxation window must not survive a successful write — it is one-shot.'
        );
    }

    // 5. OAuth registration marks the new account from the first second it exists.

    public function test_oauth_registration_marks_new_account_password_less(): void
    {
        $result = (new SocialAuth())->completePendingRegistration($this->pendingPayload());

        $this->assertSame('register', $result['action']);
        $user = UserModel::find($result['user']['id']);
        $this->assertNotNull($user);
        $this->assertFalse((bool) $user->has_self_set_password);
        // T-14-08 (14-REVIEW.md): registration-time flagging is a VERIFIED
        // placeholder, distinct from the ambiguous v3.4.0 migration backfill.
        $this->assertSame('oauth_registration', $user->password_bootstrap_source);
    }

    // 6. CR-01 (14-REVIEW.md): a bearer token alone must NOT be sufficient.
    //
    // Negative probe performed manually for this behaviour (documented in
    // 14-REVIEW.md's "CR-01 / WR-01 resolution" section and the plan Summary): with
    // ApiController::changePassword()'s confirmation-code branch temporarily reverted
    // to fall straight through to the password write (the pre-fix shape), this test
    // goes RED — the "attacker" call succeeds and the password changes. Restoring the
    // fix returns it to GREEN. This is a genuine, firing probe, not a tautology.

    public function test_stolen_token_alone_cannot_complete_relaxed_password_change(): void
    {
        $user = $this->makeUser(['email' => 'oauth-stolen@example.tld'], false);
        $this->linkOAuth($user, 'google');

        $this->spyMail();

        // The attacker holds nothing but a valid bearer JWT for this account (exactly
        // what authedRequest() mints) — no mailbox access, no password. First call:
        // issues a confirmation code by mail, but must NOT touch the password.
        $first = (new ApiController())->changePassword($this->authedRequest($user, [
            'password' => 'AttackerChosen1',
            'password_confirmation' => 'AttackerChosen1',
        ]));
        $this->assertSame(428, $first->getStatusCode());

        $user = $user->fresh();
        $this->assertTrue(
            Hash::check('placeholder-not-asserted-1', $user->password),
            'CR-01: possessing a bearer token alone must not change the password.'
        );
        $this->assertFalse((bool) $user->has_self_set_password);

        // The attacker cannot read the account's mailbox, so guesses/forges a code.
        $second = (new ApiController())->changePassword($this->authedRequest($user, [
            'password' => 'AttackerChosen1',
            'password_confirmation' => 'AttackerChosen1',
            'password_bootstrap_code' => 'GUESSED1',
        ]));
        $this->assertSame(422, $second->getStatusCode());

        $user = $user->fresh();
        $this->assertTrue(
            Hash::check('placeholder-not-asserted-1', $user->password),
            'CR-01: a wrong/forged confirmation code must not change the password either.'
        );
        $this->assertFalse(
            (bool) $user->has_self_set_password,
            'The cohort flag must remain false — no trusted write ever occurred.'
        );
    }

    public function test_confirmation_code_is_single_use_and_time_limited(): void
    {
        // Model-level proof of the two properties the "short-lived, single-use" claim
        // depends on, independent of the controller's disarm-on-success side effect
        // (which would otherwise mask a code being reusable within the same cohort).
        $user = $this->makeUser(['email' => 'oauth-code-props@example.tld'], false);

        $code = $user->issuePasswordBootstrapCode();

        // Wrong code never verifies and never consumes the real one.
        $this->assertFalse($user->verifyPasswordBootstrapCode('WRONGCODE'));
        $this->assertTrue($user->verifyPasswordBootstrapCode($code), 'The correct code must verify.');

        // Single-use: the same code must not verify a second time.
        $this->assertFalse(
            $user->verifyPasswordBootstrapCode($code),
            'A confirmation code must not be replayable after a successful verification.'
        );

        // Time-limited: a fresh code manually pushed past its expiry must not verify,
        // even though the hash comparison would otherwise succeed.
        $expiredCode = $user->issuePasswordBootstrapCode();
        $user->password_bootstrap_code_expires_at = \Carbon\Carbon::now()->subMinute();
        $user->forceSave();
        $this->assertFalse(
            $user->fresh()->verifyPasswordBootstrapCode($expiredCode),
            'An expired confirmation code must not verify even if the value matches.'
        );
    }

    // 7. WR-01 (14-REVIEW.md): concurrent unlink cannot strip the last identity.

    /**
     * Negative-probe proof that the OLD check-then-act guard shape really was
     * exploitable by two overlapping requests, reproduced mechanically (no real OS
     * threads available inside PHPUnit): both "requests" read the SAME pre-delete
     * identity count -- exactly what two concurrent HTTP requests would observe if
     * they interleave between the read and the write -- and then both perform the
     * unconditional low-level delete the old code used
     * (User::unlinkOAuthProvider(), still present and still unconditional).
     *
     * This intentionally does NOT go through SocialAuth::onUnlinkOAuth() (the fixed
     * entry point) — it exists to prove the vulnerability mechanism was real, as the
     * "RED" half of the negative probe for the next test. A revert-and-rerun of the
     * FIXED onUnlinkOAuth() back to `count() <= 1` + unlinkOAuthProvider() would NOT
     * turn the next test red by itself, because two SEQUENTIAL calls (as a single
     * PHPUnit test necessarily makes) always see the post-first-delete count even
     * under the old code -- the race only exists when two requests' reads both land
     * BEFORE either write, which is exactly what this test reproduces directly.
     */
    public function test_wr01_toctou_snapshot_would_zero_out_identities_under_old_guard_shape(): void
    {
        $user = $this->makeUser(['email' => 'oauth-race-old@example.tld'], false);
        $this->linkOAuth($user, 'google', 'race-old-google');
        $this->linkOAuth($user, 'facebook', 'race-old-facebook');

        // Both "concurrent requests" observe the same pre-delete snapshot.
        $snapshotCount = $user->oauthIdentities()->count();
        $this->assertSame(2, $snapshotCount);
        $requestAGuardPassed = $snapshotCount > 1; // old guard: NOT "<= 1" => allowed
        $requestBGuardPassed = $snapshotCount > 1;
        $this->assertTrue($requestAGuardPassed && $requestBGuardPassed);

        // Both requests, having already "passed" the (now-stale) guard, perform the
        // write half of the OLD code path.
        $user->unlinkOAuthProvider('google');
        $user->unlinkOAuthProvider('facebook');

        $this->assertSame(
            0,
            $user->fresh()->oauthIdentities()->count(),
            'This demonstrates the OLD check-then-act guard shape is exploitable: both '
            . 'deletes proceed from a shared stale snapshot and every identity is lost.'
        );
    }

    /**
     * The FIXED entry point, exercised in the same two-identity-then-both-unlink
     * shape as the negative probe above, must never reach the zero-identities
     * outcome: User::unlinkOAuthProviderIfSafe() has no separate PHP-side read to
     * share a stale snapshot with in the first place -- the guard condition is
     * embedded in the DELETE statement's own WHERE clause and is evaluated by the
     * database at the instant of the write, for every call, sequential or not.
     */
    public function test_concurrent_unlink_cannot_strip_last_identity(): void
    {
        $user = $this->makeUser(['email' => 'oauth-race@example.tld'], false);
        $this->linkOAuth($user, 'google', 'race-google');
        $this->linkOAuth($user, 'facebook', 'race-facebook');

        $resultA = $this->unlinkAs($user, 'google');
        $this->assertSame(['success' => true], $resultA);

        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage(Lang::get('golem15.user::lang.oauth.cannot_unlink_without_password'));

        try {
            $this->unlinkAs($user, 'facebook');
        } finally {
            $user = $user->fresh();
            $this->assertSame(1, $user->oauthIdentities()->count(), 'Exactly one identity must survive.');
            $this->assertTrue($user->hasOAuthProvider('facebook'));
        }
    }
}
