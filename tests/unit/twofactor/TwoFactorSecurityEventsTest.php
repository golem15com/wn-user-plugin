<?php

namespace Golem15\User\Tests\Unit\TwoFactor;

require_once __DIR__ . '/TwoFactorTestCase.php';

use Event;

/**
 * D-20 core hooks (additive): 'golem15.user.2fa.webauthn.removed' carries the
 * removed credential's name as a third argument, and
 * 'golem15.user.2fa.state_changed' [User, bool $enabledNow] fires exactly when
 * isEnabledForUser() flips during enrol, disable or remove.
 */
class TwoFactorSecurityEventsTest extends TwoFactorTestCase
{
    /** @var array<int, array> */
    private array $stateChanges = [];

    public function setUp(): void
    {
        parent::setUp();
        $this->enableTwoFactorSettings();
        $this->configureWebAuthn();

        $this->stateChanges = [];
        Event::listen('golem15.user.2fa.state_changed', function ($user, $enabledNow) {
            $this->stateChanges[] = [$user->id, $enabledNow];
        });
    }

    private function confirmTotpFor($user): void
    {
        $secret = $this->google2fa->generateSecretKey();
        $code = $this->otpAt($secret, $this->currentTimestep());

        $this->assertTrue($this->service()->confirmTotp($user, $secret, $code));
    }

    public function test_webauthn_removed_listener_receives_the_old_name_as_third_argument(): void
    {
        $user = $this->makeUser();
        $credential = $this->registerSoftKey($user, $this->softAuthenticator(), true, 'Desk key');

        $received = null;
        Event::listen('golem15.user.2fa.webauthn.removed', function (...$args) use (&$received) {
            $received = $args;
        });

        $this->assertTrue($this->service()->removeWebAuthnCredential($user, $credential->id));

        $this->assertNotNull($received, 'webauthn.removed did not fire');
        $this->assertCount(3, $received);
        $this->assertSame($user->id, $received[0]->id);
        $this->assertSame($credential->id, $received[1]);
        $this->assertSame('Desk key', $received[2]);
    }

    public function test_two_argument_removed_listeners_still_work(): void
    {
        $user = $this->makeUser();
        $credential = $this->registerSoftKey($user, $this->softAuthenticator(), true, 'Desk key');

        $calls = 0;
        Event::listen('golem15.user.2fa.webauthn.removed', function ($u, $id) use (&$calls, $credential) {
            $this->assertSame($credential->id, $id);
            $calls++;
        });

        $this->service()->removeWebAuthnCredential($user, $credential->id);

        $this->assertSame(1, $calls);
    }

    public function test_state_changed_fires_true_on_first_enrolment_only(): void
    {
        $user = $this->makeUser();

        $this->confirmTotpFor($user);
        $this->assertSame([[$user->id, true]], $this->stateChanges);

        // A second factor does not flip the state.
        $this->registerSoftKey($user, $this->softAuthenticator(), true, 'Phone');
        $this->assertSame([[$user->id, true]], $this->stateChanges);
    }

    public function test_state_changed_fires_true_when_a_passkey_is_the_first_factor(): void
    {
        $user = $this->makeUser();

        $this->registerSoftKey($user, $this->softAuthenticator(), true, 'Phone');

        $this->assertSame([[$user->id, true]], $this->stateChanges);
    }

    public function test_state_changed_fires_false_when_the_last_factor_is_disabled(): void
    {
        $user = $this->makeUser();
        $this->confirmTotpFor($user);
        $credential = $this->registerSoftKey($user, $this->softAuthenticator(), true, 'Phone');
        $this->stateChanges = [];

        // Removing one of two factors does not flip the state.
        $this->service()->removeWebAuthnCredential($user, $credential->id);
        $this->assertSame([], $this->stateChanges);

        $this->assertTrue($this->service()->disableMethod($user, 'totp'));
        $this->assertSame([[$user->id, false]], $this->stateChanges);
    }

    public function test_state_changed_fires_false_when_the_last_passkey_is_removed(): void
    {
        $user = $this->makeUser();
        $credential = $this->registerSoftKey($user, $this->softAuthenticator(), true, 'Phone');
        $this->stateChanges = [];

        $this->service()->removeWebAuthnCredential($user, $credential->id);

        $this->assertSame([[$user->id, false]], $this->stateChanges);
    }

    public function test_reconfirming_an_enabled_totp_does_not_fire_state_changed(): void
    {
        $user = $this->makeUser();
        $this->confirmTotpFor($user);
        $this->stateChanges = [];

        $this->confirmTotpFor($user);

        $this->assertSame([], $this->stateChanges);
    }
}
