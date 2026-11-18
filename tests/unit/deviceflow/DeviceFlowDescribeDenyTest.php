<?php

namespace Golem15\User\Tests\Unit\DeviceFlow;

require_once __DIR__ . '/DeviceFlowTestCase.php';

use Carbon\Carbon;
use Golem15\User\Models\DeviceAuthSession;

/**
 * D-05 / D-06: a signed-in browser can describe a pending verifier session
 * (what is asking, no account data) and refuse it.
 */
class DeviceFlowDescribeDenyTest extends DeviceFlowTestCase
{
    protected const CHROME_LINUX_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

    // ---- describe -----------------------------------------------------------

    public function test_describe_returns_only_the_whitelisted_keys_while_pending(): void
    {
        $viewer = $this->makeUser();
        [$token, , $init] = $this->initiateRedeemable(['device_name' => 'WavePath Desktop (Linux)'], self::CHROME_LINUX_UA);

        [$status, $body] = $this->describe($token, $viewer);

        $this->assertSame(200, $status, json_encode($body));
        $this->assertTrue($body['success']);
        $data = $body['data'];
        $keys = array_keys($data);
        sort($keys);
        $this->assertSame(['app', 'created_at', 'device_name', 'expires_in', 'ip', 'os', 'short_code', 'status'], $keys);
        $this->assertSame('pending', $data['status']);
        $this->assertSame($init['data']['short_code'], $data['short_code']);
        $this->assertSame('WavePath Desktop (Linux)', $data['device_name']);
        $this->assertSame('127.0.0.1', $data['ip']);
        $this->assertNotFalse(Carbon::parse($data['created_at']));
        $this->assertGreaterThan(0, $data['expires_in']);
        $this->assertLessThanOrEqual(300, $data['expires_in']);

        $raw = json_encode($body);
        $session = $this->deviceSession($token);
        $this->assertStringNotContainsString($token, $raw);
        $this->assertStringNotContainsString((string) $session->code_challenge, $raw);
        $this->assertStringNotContainsString($viewer->email, $raw);
        $this->assertStringNotContainsString('user_id', $raw);
        $this->assertStringNotContainsString('code_challenge', $raw);
    }

    public function test_describe_reads_the_raw_device_name(): void
    {
        $viewer = $this->makeUser();

        // Null column: the model accessor would invent "Linux PC"; describe says null.
        [$token] = $this->initiateRedeemable([], self::CHROME_LINUX_UA);
        $this->assertSame('Linux PC', $this->deviceSession($token)->device_name);
        [, $body] = $this->describe($token, $viewer);
        $this->assertNull($body['data']['device_name']);

        // Longer than 64: cut to the first 64 characters.
        $long = str_repeat('Ž', 70);
        [$token] = $this->initiateRedeemable(['device_name' => $long], self::CHROME_LINUX_UA);
        [, $body] = $this->describe($token, $viewer);
        $this->assertSame(mb_substr($long, 0, 64), $body['data']['device_name']);
    }

    public function test_describe_parses_app_and_os_from_the_user_agent(): void
    {
        $viewer = $this->makeUser();

        [$token] = $this->initiateRedeemable([], self::CHROME_LINUX_UA);
        [, $body] = $this->describe($token, $viewer);
        $this->assertSame('Chrome', $body['data']['app']);
        $this->assertSame('Linux', $body['data']['os']);

        [$token] = $this->initiateRedeemable([], 'curl-ish/1.0');
        [, $body] = $this->describe($token, $viewer);
        $this->assertNull($body['data']['app']);
        $this->assertNull($body['data']['os']);
    }

    public function test_describe_of_a_non_pending_session_returns_only_its_status(): void
    {
        $viewer = $this->makeUser();

        // confirmed
        [$token, $verifier] = $this->initiateRedeemable();
        $this->confirmAs($viewer, $token);
        [$status, $body] = $this->describe($token, $viewer);
        $this->assertSame(200, $status);
        $this->assertSame(['success' => true, 'data' => ['status' => 'confirmed']], $body);

        // used
        $this->redeem($token, $verifier);
        [, $body] = $this->describe($token, $viewer);
        $this->assertSame(['status' => 'used'], $body['data']);

        // denied
        [$token] = $this->initiateRedeemable();
        $this->deny($token, $viewer);
        [, $body] = $this->describe($token, $viewer);
        $this->assertSame(['status' => 'denied'], $body['data']);

        // expired
        [$token] = $this->initiateRedeemable();
        Carbon::setTestNow(Carbon::now()->addMinutes(6));
        [, $body] = $this->describe($token, $viewer);
        $this->assertSame(['status' => 'expired'], $body['data']);
    }

    public function test_describe_of_a_legacy_or_unknown_session_is_404(): void
    {
        $viewer = $this->makeUser();
        [, $init] = $this->initiate([]);

        [$status, $body] = $this->describe($init['data']['token'], $viewer);
        $this->assertSame(404, $status);
        $this->assertSame(['error' => 'Session not found'], $body);

        [$status] = $this->describe(str_repeat('b', 64), $viewer);
        $this->assertSame(404, $status);
    }

    public function test_describe_and_deny_need_a_signed_in_caller(): void
    {
        [$token] = $this->initiateRedeemable();

        [$status, $body] = $this->describe($token, null);
        $this->assertSame(401, $status);
        $this->assertSame(['error' => 'Unauthorized'], $body);

        [$status] = $this->deny($token, null);
        $this->assertSame(401, $status);
        $this->assertSame(DeviceAuthSession::STATUS_PENDING, $this->deviceSession($token)->status);
    }

    public function test_describe_and_deny_reject_a_malformed_token(): void
    {
        $viewer = $this->makeUser();

        [$status, $body] = $this->describe('short', $viewer);
        $this->assertSame(422, $status);
        $this->assertSame('Validation failed', $body['error']);

        [$status] = $this->deny('short', $viewer);
        $this->assertSame(422, $status);
    }

    // ---- deny ---------------------------------------------------------------

    public function test_deny_refuses_a_pending_session_for_good(): void
    {
        $viewer = $this->makeUser();
        [$token, $verifier] = $this->initiateRedeemable();

        [$status, $body] = $this->deny($token, $viewer);
        $this->assertSame(200, $status);
        $this->assertSame(['success' => true, 'data' => ['status' => 'denied']], $body);

        $session = $this->deviceSession($token);
        $this->assertSame(DeviceAuthSession::STATUS_REVOKED, $session->status);
        $this->assertNotNull($session->denied_at);

        [, $body] = $this->poll($token, $verifier);
        $this->assertSame('denied', $body['data']['status']);

        [$status, $body] = $this->redeem($token, $verifier);
        $this->assertSame(410, $status);
        $this->assertSame('access_denied', $body['code']);

        [$status, $body] = $this->confirmAs($viewer, $token);
        $this->assertSame(400, $status);
        $this->assertSame(['error' => 'Invalid or expired code'], $body);
    }

    public function test_deny_of_a_non_pending_session_is_409_with_its_status(): void
    {
        $viewer = $this->makeUser();
        [$token] = $this->initiateRedeemable();
        $this->confirmAs($viewer, $token);

        [$status, $body] = $this->deny($token, $viewer);
        $this->assertSame(409, $status);
        $this->assertSame(['error' => 'Session is not pending', 'status' => 'confirmed'], $body);
        $this->assertSame(DeviceAuthSession::STATUS_CONFIRMED, $this->deviceSession($token)->status);
    }

    public function test_deny_of_a_legacy_session_is_404(): void
    {
        $viewer = $this->makeUser();
        [, $init] = $this->initiate([]);
        $token = $init['data']['token'];

        [$status, $body] = $this->deny($token, $viewer);
        $this->assertSame(404, $status);
        $this->assertSame(['error' => 'Session not found'], $body);
        $this->assertSame(DeviceAuthSession::STATUS_PENDING, $this->deviceSession($token)->status);
    }
}
