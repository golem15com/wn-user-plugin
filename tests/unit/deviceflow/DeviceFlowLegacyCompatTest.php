<?php

namespace Golem15\User\Tests\Unit\DeviceFlow;

require_once __DIR__ . '/DeviceFlowTestCase.php';

use Golem15\User\Components\DeviceAuth;
use Golem15\User\Controllers\ApiController;
use Golem15\User\Facades\Auth;
use Golem15\User\Models\DeviceAuthSession;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;

/**
 * D-09 / D-14 + the core-plugin additive rule: the legacy device-flow paths
 * (status by path token, short-code authorize, the CMS DeviceAuth component)
 * can never complete or leak a verifier session, and behave exactly as before
 * for sessions created without a code_challenge.
 */
class DeviceFlowLegacyCompatTest extends DeviceFlowTestCase
{
    /**
     * @return array{0: int, 1: array}
     */
    protected function legacyStatus(string $token): array
    {
        return $this->callJson(fn () => (new ApiController())->deviceAuthStatus($this->request([], null, 'GET'), $token));
    }

    protected function checkAuthStatusViaComponent(string $token): array
    {
        $request = Request::create('/device', 'POST', ['token' => $token]);
        $this->app->instance('request', $request);
        Facade::clearResolvedInstance('request');

        return (new DeviceAuth())->onCheckAuthStatus();
    }

    // ---- GET devices/status/{token} -------------------------------------------

    public function test_legacy_status_hides_a_verifier_session(): void
    {
        $user = $this->makeUser();
        [$token] = $this->initiateRedeemable();
        $this->confirmAs($user, $token);
        $before = $this->deviceSession($token)->getAttributes();

        [$status, $body] = $this->legacyStatus($token);

        $this->assertSame(404, $status);
        $this->assertSame(['error' => 'Session not found'], $body);
        $this->assertSame($before, $this->deviceSession($token)->getAttributes());
    }

    public function test_legacy_status_still_returns_user_id_for_a_legacy_session(): void
    {
        $user = $this->makeUser();
        [, $init] = $this->initiate([]);
        $token = $init['data']['token'];

        [$status, $body] = $this->legacyStatus($token);
        $this->assertSame(200, $status);
        $this->assertSame('pending', $body['data']['status']);

        $this->confirmAs($user, $token);

        [$status, $body] = $this->legacyStatus($token);
        $this->assertSame(200, $status);
        $this->assertSame('confirmed', $body['data']['status']);
        $this->assertSame((int) $user->id, (int) $body['data']['user_id']);
    }

    // ---- POST devices/authorize --------------------------------------------

    public function test_short_code_authorize_refuses_a_verifier_session(): void
    {
        $user = $this->makeUser();
        [$token, , $init] = $this->initiateRedeemable();

        [$status, $body] = $this->authorizeShortCodeAs($user, $init['data']['short_code']);

        $this->assertSame(400, $status);
        $this->assertSame(['error' => 'Invalid or expired code'], $body);
        $session = $this->deviceSession($token);
        $this->assertSame(DeviceAuthSession::STATUS_PENDING, $session->status);
        $this->assertNull($session->user_id);
    }

    public function test_short_code_authorize_still_works_for_a_legacy_session(): void
    {
        $user = $this->makeUser();
        [, $init] = $this->initiate([]);

        [$status, $body] = $this->authorizeShortCodeAs($user, $init['data']['short_code']);

        $this->assertSame(200, $status);
        $this->assertTrue($body['success']);
        $session = $this->deviceSession($init['data']['token']);
        $this->assertSame(DeviceAuthSession::STATUS_CONFIRMED, $session->status);
        $this->assertSame((int) $user->id, (int) $session->user_id);
    }

    public function test_legacy_initiate_keeps_its_response_and_five_minute_window(): void
    {
        [$status, $body] = $this->initiate(['device_name' => 'Kiosk']);

        $this->assertSame(200, $status);
        foreach (['token', 'short_code', 'auth_url', 'expires_at'] as $key) {
            $this->assertArrayHasKey($key, $body['data']);
        }
        $this->assertStringEndsWith('/device/scan/' . $body['data']['token'], $body['data']['auth_url']);
        $session = $this->deviceSession($body['data']['token']);
        $this->assertNull($session->code_challenge);
        $this->assertFalse($session->isRedeemable());
        $this->assertEqualsWithDelta(300, $session->expires_at->getTimestamp() - $session->created_at->getTimestamp(), 2);
    }

    // ---- CMS DeviceAuth component ---------------------------------------------

    public function test_component_never_logs_in_a_verifier_session(): void
    {
        $user = $this->makeUser();
        [$token] = $this->initiateRedeemable();
        $this->confirmAs($user, $token);

        $result = $this->checkAuthStatusViaComponent($token);

        $this->assertSame(['status' => 'expired', 'message' => 'Authorization token not found'], $result);
        $this->assertFalse(Auth::check());
        $this->assertSame(DeviceAuthSession::STATUS_CONFIRMED, $this->deviceSession($token)->status);
    }

    public function test_component_still_logs_in_a_confirmed_legacy_session(): void
    {
        $user = $this->makeUser();
        [, $init] = $this->initiate([]);
        $token = $init['data']['token'];
        $this->confirmAs($user, $token);

        $result = $this->checkAuthStatusViaComponent($token);

        $this->assertSame('confirmed', $result['status']);
        $this->assertTrue(Auth::check());
        $this->assertSame((int) $user->id, (int) Auth::getUser()->id);
        $this->assertSame(DeviceAuthSession::STATUS_USED, $this->deviceSession($token)->status);
    }
}
