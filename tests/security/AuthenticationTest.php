<?php namespace Golem15\User\Tests\Security;

use Golem15\User\Tests\UserPluginTestCase;

/**
 * Security PoC tests for HIGH findings USER-003, USER-004, USER-005.
 * Each test method is named test_user_NNN_<short_slug> and references
 * the finding in .planning/audit/plugins/golem15/user/FINDINGS.md.
 *
 * @group security
 *
 * Per Phase 7 D-20: PoC tests use HTTP-only + unit fidelity.
 * These tests MUST FAIL on current code (red-bar regression locks).
 * The remediation milestone's fixes will turn them green.
 */
class AuthenticationTest extends UserPluginTestCase
{
    /**
     * USER-003: OAuth flow uses stateless() bypassing CSRF state parameter validation.
     *
     * The SocialAuth component calls Socialite::driver($provider)->stateless()->redirect()
     * and stateless()->user(), disabling the built-in state parameter (CSRF protection).
     * Without state validation, Login CSRF attacks are possible.
     *
     * EXPECTATION (post-fix): OAuth flow uses state parameter validation -- either
     * Socialite's default stateful mode, or a custom signed state token.
     * TODAY (pre-fix): stateless() is called, disabling state validation entirely.
     * This assertion FAILS because stateless() is present without compensating controls.
     *
     * @test
     * @group security
     * @see .planning/audit/plugins/golem15/user/FINDINGS.md #USER-003
     * @see .planning/audit/DASHBOARD.md #USER-003
     */
    public function test_user_003_oauth_stateless_csrf_bypass(): void
    {
        $source = file_get_contents(
            dirname(__DIR__, 2) . '/components/SocialAuth.php'
        );

        // Check if stateless() is still called without compensating state validation
        $usesStateless = str_contains($source, '->stateless()');

        // A secure implementation either:
        // 1. Does not use stateless() (uses default stateful mode), or
        // 2. Uses stateless() but implements custom state parameter validation
        $hasCustomStateValidation = (
            str_contains($source, 'state')
            && (
                str_contains($source, 'verifyState')
                || str_contains($source, 'verifyOAuthState')
                || str_contains($source, 'validateState')
                || str_contains($source, 'session()->get(\'state\')')
                || str_contains($source, 'csrf')
                || str_contains($source, 'hash_hmac')
            )
        );

        $this->assertFalse(
            $usesStateless && !$hasCustomStateValidation,
            'USER-003: SocialAuth component uses Socialite::driver()->stateless() which '
            . 'disables CSRF state parameter validation. An attacker can perform Login CSRF: '
            . 'initiate OAuth with their own account, capture the callback URL, and trick '
            . 'the victim into visiting it -- linking the attacker\'s OAuth identity to the '
            . 'victim\'s session or creating a new account under the attacker\'s identity. '
            . 'Post-fix: implement custom state parameter validation or use Socialite\'s '
            . 'default stateful mode.'
        );
    }

    /**
     * USER-004: Verify-pin endpoints lack rate limiting.
     *
     * The pin-login endpoint has throttle:pin-login middleware (10 attempts/min),
     * but verify-pin and verify-family-member-pin have only the general throttle:user-api
     * (120 requests/min). A 4-digit PIN can be brute-forced in ~83 minutes at 120/min.
     *
     * EXPECTATION (post-fix): verify-pin and verify-family-member-pin use
     * throttle:pin-login (or equivalent strict rate limiting).
     * TODAY (pre-fix): these endpoints use only the general API throttle.
     * This assertion FAILS because the strict rate limiting is absent.
     *
     * @test
     * @group security
     * @see .planning/audit/plugins/golem15/user/FINDINGS.md #USER-004
     * @see .planning/audit/DASHBOARD.md #USER-004
     */
    public function test_user_004_verify_pin_missing_rate_limit(): void
    {
        $source = file_get_contents(
            dirname(__DIR__, 2) . '/routes.php'
        );

        // USER-004 covers BOTH verify-pin AND verify-family-member-pin (both accept
        // 4-digit PINs). The regression lock must assert strict throttling on each
        // route block independently, otherwise removing the throttle from one route
        // would slip through.
        $assertRouteHasStrictThrottle = function (string $routeName) use ($source): void {
            $pos = strpos($source, "'{$routeName}'");
            $this->assertNotFalse(
                $pos,
                "USER-004: Could not locate {$routeName} route in routes.php to verify "
                . 'rate limiting middleware. Manual verification needed.'
            );

            // Inspect the next 200 chars of source -- the chained ->middleware(...) call
            // appears within this window for the route definitions in routes.php.
            $routeBlock = substr($source, $pos, 200);

            $hasStrictThrottle = (
                str_contains($routeBlock, 'throttle:pin-login')
                || str_contains($routeBlock, 'throttle:verify-pin')
                || str_contains($routeBlock, 'throttle:5,')
            );

            $this->assertTrue(
                $hasStrictThrottle,
                "USER-004: {$routeName} route does not have strict rate limiting middleware. "
                . 'pin-login has throttle:pin-login (10/min) but this route would otherwise '
                . 'fall back to the group-level throttle:user-api (120/min). A 4-digit PIN '
                . '(10,000 possibilities) can be brute-forced in ~83 minutes at 120 '
                . 'requests/min. GDPR-Art8-Applicable: YES (child PIN brute force). '
                . "Post-fix: apply ->middleware('throttle:pin-login') to the {$routeName} route."
            );
        };

        $assertRouteHasStrictThrottle('verify-pin');
        $assertRouteHasStrictThrottle('verify-family-member-pin');
    }

    /**
     * USER-005: TwoFactorService type confusion causes 2FA enforcement to silently fail.
     *
     * Settings::get() returns a Collection where scalar is expected. Comparisons
     * like $enforcement === 'disabled' (Collection vs string) always evaluate to false,
     * and $enforcement !== 'enforced' always evaluates to true. The 2FA enforcement
     * configuration is unreliable.
     *
     * EXPECTATION (post-fix): Settings::get('two_factor_enforcement') is cast to
     * string before comparison, or the TwoFactorService uses a type-safe getter.
     * TODAY (pre-fix): No cast exists; Collection is compared to string literals.
     * This assertion FAILS because the type-safe pattern is absent.
     *
     * @test
     * @group security
     * @see .planning/audit/plugins/golem15/user/FINDINGS.md #USER-005
     * @see .planning/audit/DASHBOARD.md #USER-005
     */
    public function test_user_005_twofactor_type_confusion(): void
    {
        $twoFactorServicePath = dirname(__DIR__, 2) . '/classes/twofactor/TwoFactorService.php';

        if (!file_exists($twoFactorServicePath)) {
            // Try alternative path
            $twoFactorServicePath = dirname(__DIR__, 2) . '/classes/TwoFactorService.php';
        }

        if (!file_exists($twoFactorServicePath)) {
            $this->fail(
                'USER-005: Could not locate TwoFactorService.php. '
                . 'Manual verification needed for type confusion issue.'
            );
            return;
        }

        $source = file_get_contents($twoFactorServicePath);

        // A secure implementation casts the Settings::get() value to string
        // before comparing with enforcement mode strings.
        // Note: code uses "UserSettings" alias for Golem15\User\Models\Settings
        $hasTypeSafeCast = (
            str_contains($source, "(string) Settings::get")
            || str_contains($source, "(string)Settings::get")
            || str_contains($source, "(string) UserSettings::get")
            || str_contains($source, "(string)UserSettings::get")
            || str_contains($source, "strval(Settings::get")
            || str_contains($source, "strval(UserSettings::get")
        );

        $this->assertTrue(
            $hasTypeSafeCast,
            'USER-005: TwoFactorService compares Settings::get() return value (Collection) '
            . 'against string literals without casting. This causes 2FA enforcement to '
            . 'silently fail: $enforcement === \'disabled\' is always false (Collection !== '
            . 'string), and $enforcement !== \'enforced\' is always true. Users who should '
            . 'be required to use 2FA may bypass it. '
            . 'GDPR-Art8-Applicable: YES (child account 2FA bypass). '
            . 'Post-fix: cast Settings::get(\'two_factor_enforcement\') to string before comparison.'
        );
    }
}
