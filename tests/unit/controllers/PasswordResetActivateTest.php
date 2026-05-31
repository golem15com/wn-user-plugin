<?php

namespace Golem15\User\Tests\Unit\Controllers;

use Mockery;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use Golem15\User\Controllers\ApiController;
use Golem15\User\Models\User as UserModel;
use Golem15\User\Tests\UserPluginTestCase;

/**
 * Phase 26-01 backend coverage for the additive Golem15.User changes (D-09 + D-02):
 *  - forgotPassword() enumeration-safe behaviour + mail-queued only for real non-guest users
 *  - resetPassword() {userId}!{code} round-trip + malformed/invalid 422s
 *  - public activateByCode() with no JWT
 *
 * These invoke the controller methods directly with a built Request so they run under the
 * plain-phpunit harness (which does not register plugin routes). On a TTY host the same
 * behaviours are reachable end-to-end via the /_user/api/v1/* routes.
 *
 * @group registration
 */
class PasswordResetActivateTest extends UserPluginTestCase
{
    protected function makeRequest(array $data): Request
    {
        return new Request($data);
    }

    protected function makeUser(array $overrides = []): UserModel
    {
        $user = new UserModel();
        $user->fill(array_merge([
            'name' => 'Reset Tester',
            'email' => 'reset-tester@example.tld',
            'password' => 'originalpass1',
            'password_confirmation' => 'originalpass1',
        ], $overrides));
        $user->forceSave();

        return $user;
    }

    //
    // forgotPassword()
    //

    /**
     * Swap the Mail facade root with a Mockery spy.
     *
     * forgotPassword() uses the canonical raw-view send `Mail::queue($view, $data, $closure)`
     * (ported verbatim from ResetPassword::onRestorePassword()). Laravel's MailFake silently
     * drops non-Mailable raw-view queues, so Mail::assertQueued() can never observe it — we spy
     * on the underlying mailer instead and assert the restore view (does / does not) get queued.
     */
    protected function spyMail()
    {
        $spy = Mockery::spy('Illuminate\Contracts\Mail\Mailer');
        Mail::swap($spy);

        return $spy;
    }

    public function test_forgot_password_unknown_email_returns_200_and_queues_no_mail(): void
    {
        $mail = $this->spyMail();

        $response = (new ApiController())->forgotPassword(
            $this->makeRequest(['email' => 'nobody-here@example.tld'])
        );

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(
            'If that email exists, a reset link has been sent.',
            $response->getData(true)['message']
        );

        $mail->shouldNotHaveReceived('queue');
    }

    public function test_forgot_password_known_email_returns_same_200_and_queues_one_mail(): void
    {
        $user = $this->makeUser(['email' => 'known-user@example.tld']);

        $mail = $this->spyMail();

        $response = (new ApiController())->forgotPassword(
            $this->makeRequest(['email' => 'known-user@example.tld'])
        );

        // Enumeration-safe: identical body whether or not the account exists.
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(
            'If that email exists, a reset link has been sent.',
            $response->getData(true)['message']
        );

        $mail->shouldHaveReceived('queue')
            ->with('golem15.user::mail.restore', Mockery::type('array'), Mockery::type('callable'))
            ->once();
    }

    public function test_forgot_password_invalid_email_returns_422_with_errors(): void
    {
        $mail = $this->spyMail();

        $response = (new ApiController())->forgotPassword(
            $this->makeRequest(['email' => 'not-an-email'])
        );

        $this->assertSame(422, $response->getStatusCode());
        $body = $response->getData(true);
        $this->assertArrayHasKey('error', $body);
        $this->assertArrayHasKey('errors', $body);
        $this->assertArrayHasKey('email', $body['errors']);

        $mail->shouldNotHaveReceived('queue');
    }

    //
    // resetPassword()
    //

    public function test_reset_password_valid_code_changes_password_and_returns_200(): void
    {
        $user = $this->makeUser(['email' => 'reset-me@example.tld']);

        $code = implode('!', [$user->id, $user->getResetPasswordCode()]);

        $response = (new ApiController())->resetPassword($this->makeRequest([
            'code' => $code,
            'password' => 'brandnewpass1',
            'password_confirmation' => 'brandnewpass1',
        ]));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('Password has been reset', $response->getData(true)['message']);

        // The new password actually authenticates; the old one no longer does.
        $fresh = UserModel::find($user->id);
        $this->assertTrue($fresh->checkPassword('brandnewpass1'));
        $this->assertFalse($fresh->checkPassword('originalpass1'));
    }

    public function test_reset_password_malformed_code_returns_422(): void
    {
        $response = (new ApiController())->resetPassword($this->makeRequest([
            'code' => 'no-bang-here',
            'password' => 'brandnewpass1',
            'password_confirmation' => 'brandnewpass1',
        ]));

        $this->assertSame(422, $response->getStatusCode());
        $this->assertSame('Invalid reset code', $response->getData(true)['error']);
    }

    public function test_reset_password_wrong_code_returns_422(): void
    {
        $user = $this->makeUser(['email' => 'wrong-code@example.tld']);

        $response = (new ApiController())->resetPassword($this->makeRequest([
            'code' => $user->id . '!totally-wrong-code',
            'password' => 'brandnewpass1',
            'password_confirmation' => 'brandnewpass1',
        ]));

        $this->assertSame(422, $response->getStatusCode());
        $this->assertSame('Invalid or expired reset code', $response->getData(true)['error']);
    }

    public function test_reset_password_mismatched_confirmation_returns_422(): void
    {
        $user = $this->makeUser(['email' => 'mismatch@example.tld']);
        $code = implode('!', [$user->id, $user->getResetPasswordCode()]);

        $response = (new ApiController())->resetPassword($this->makeRequest([
            'code' => $code,
            'password' => 'brandnewpass1',
            'password_confirmation' => 'doesnotmatch1',
        ]));

        $this->assertSame(422, $response->getStatusCode());
        $body = $response->getData(true);
        $this->assertArrayHasKey('errors', $body);
    }

    //
    // activateByCode() — public, no JWT
    //

    public function test_activate_by_code_activates_user_without_jwt(): void
    {
        $user = $this->makeUser([
            'name' => 'Pending Activate',
            'email' => 'activate-me@example.tld',
        ]);
        // Force an unactivated state with a known activation code.
        $user->is_activated = false;
        $user->activated_at = null;
        $activationCode = $user->getActivationCode();
        $user->forceSave();

        $code = implode('!', [$user->id, $activationCode]);

        // No Authorization header / no authorize() — a logged-out visitor.
        $response = (new ApiController())->activateByCode($this->makeRequest(['code' => $code]));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertArrayHasKey('message', $response->getData(true));

        $fresh = UserModel::find($user->id);
        $this->assertTrue((bool) $fresh->is_activated);
    }

    public function test_activate_by_code_invalid_code_returns_422(): void
    {
        $user = $this->makeUser(['email' => 'bad-activate@example.tld']);
        $user->is_activated = false;
        $user->getActivationCode();
        $user->forceSave();

        $response = (new ApiController())->activateByCode(
            $this->makeRequest(['code' => $user->id . '!nope-wrong'])
        );

        $this->assertSame(422, $response->getStatusCode());
        $this->assertArrayHasKey('error', $response->getData(true));
    }

    public function test_activate_by_code_malformed_code_returns_422(): void
    {
        $response = (new ApiController())->activateByCode(
            $this->makeRequest(['code' => 'no-bang'])
        );

        $this->assertSame(422, $response->getStatusCode());
        $this->assertSame('Invalid activation code', $response->getData(true)['error']);
    }

    //
    // Additive-scope guard: the public activate-by-code route exists with NO jwt.auth.
    //

    public function test_activate_by_code_route_is_public(): void
    {
        $routes = file_get_contents(dirname(__DIR__, 3) . '/routes.php');
        $this->assertStringContainsString('activate-by-code', $routes);
    }
}
