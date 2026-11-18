<?php

namespace Golem15\User\Tests\Unit\DeviceFlow;

require_once __DIR__ . '/DeviceFlowTestCase.php';

use Carbon\Carbon;
use Config;
use Event;
use Golem15\User\Models\DeviceAuthSession;
use Golem15\User\Models\Settings;
use Golem15\User\Plugin;
use System\Behaviors\SettingsModel;
use Winter\Storm\Support\Facades\Yaml;

/**
 * D-11 / D-13: the pending and redeem windows are operator Settings with the
 * old defaults, and a successful redeem has an additive security mail template
 * plus an event payload a host can send it from.
 */
class DeviceFlowLifetimeTest extends DeviceFlowTestCase
{
    protected function setSetting(string $key, $value): void
    {
        Settings::set($key, $value);
        SettingsModel::clearInternalCache();
    }

    protected function mailTemplatePath(): string
    {
        return __DIR__ . '/../../../views/mail/security_device_signed_in.htm';
    }

    // ---- defaults -------------------------------------------------------------

    public function test_defaults_are_five_minutes_and_sixty_seconds(): void
    {
        $this->assertSame(5, DeviceAuthSession::pendingTtlMinutes());
        $this->assertSame(60, DeviceAuthSession::redeemTtlSeconds());

        Carbon::setTestNow(Carbon::now()->startOfSecond());
        [$status, $body] = $this->initiate([]);
        $this->assertSame(200, $status);
        $this->assertSame(300, $body['data']['expires_in']);
        $this->assertSame(
            Carbon::now()->addMinutes(5)->getTimestamp(),
            $this->deviceSession($body['data']['token'])->expires_at->getTimestamp()
        );
    }

    public function test_settings_defaults_come_from_init_settings_data(): void
    {
        $instance = Settings::instance();
        $this->assertSame(5, (int) $instance->device_auth_pending_ttl);
        $this->assertSame(60, (int) $instance->device_auth_redeem_ttl);

        // A host can change the default through plugin config, as for the other keys.
        Config::set('golem15.user::deviceAuthPendingTtl', 10);
        Config::set('golem15.user::deviceAuthRedeemTtl', 45);
        Settings::resetDefault();
        SettingsModel::clearInternalCache();

        $this->assertSame(10, DeviceAuthSession::pendingTtlMinutes());
        $this->assertSame(45, DeviceAuthSession::redeemTtlSeconds());
    }

    public function test_backend_settings_form_has_both_lifetime_fields(): void
    {
        $fields = Yaml::parseFile(__DIR__ . '/../../../models/settings/fields.yaml');
        $tabs = $fields['tabs']['fields'] ?? [];

        foreach (['device_auth_pending_ttl' => 5, 'device_auth_redeem_ttl' => 60] as $key => $default) {
            $this->assertArrayHasKey($key, $tabs);
            $this->assertSame('number', $tabs[$key]['type']);
            $this->assertSame($default, $tabs[$key]['default']);
            $this->assertSame('golem15.user::lang.settings.two_factor_tab', $tabs[$key]['tab']);
            $this->assertArrayNotHasKey('trigger', $tabs[$key]);
            $this->assertNotSame($tabs[$key]['label'], trans($tabs[$key]['label']), "missing lang key for {$key}");
            $this->assertNotSame($tabs[$key]['comment'], trans($tabs[$key]['comment']), "missing lang comment for {$key}");
        }
    }

    // ---- configured windows -----------------------------------------------------

    public function test_pending_ttl_setting_drives_initiate(): void
    {
        $this->setSetting('device_auth_pending_ttl', 10);

        Carbon::setTestNow(Carbon::now()->startOfSecond());
        [$status, $body] = $this->initiate([]);
        $this->assertSame(200, $status);
        $this->assertSame(600, $body['data']['expires_in']);
        $this->assertSame(
            Carbon::now()->addMinutes(10)->getTimestamp(),
            $this->deviceSession($body['data']['token'])->expires_at->getTimestamp()
        );
    }

    public function test_redeem_ttl_setting_drives_the_window_after_confirm(): void
    {
        $this->setSetting('device_auth_redeem_ttl', 30);
        $user = $this->makeUser();
        [$token] = $this->initiateRedeemable();

        Carbon::setTestNow(Carbon::now()->startOfSecond());
        $this->confirmAs($user, $token);

        $this->assertSame(
            Carbon::now()->addSeconds(30)->getTimestamp(),
            $this->deviceSession($token)->expires_at->getTimestamp()
        );
    }

    public function test_a_late_confirm_still_gets_the_full_redeem_window(): void
    {
        $this->setSetting('device_auth_pending_ttl', 10);
        $user = $this->makeUser();

        $start = Carbon::now()->startOfSecond();
        Carbon::setTestNow($start);
        [$token, $verifier] = $this->initiateRedeemable();
        [, $legacy] = $this->initiate([]);
        $legacyToken = $legacy['data']['token'];
        $legacyExpiry = $this->deviceSession($legacyToken)->expires_at->getTimestamp();

        // 9 min 50 s later the browser confirms both.
        Carbon::setTestNow($start->copy()->addMinutes(9)->addSeconds(50));
        $this->confirmAs($user, $token);
        $this->confirmAs($user, $legacyToken);

        $this->assertSame(Carbon::now()->addSeconds(60)->getTimestamp(), $this->deviceSession($token)->expires_at->getTimestamp());
        $this->assertSame($legacyExpiry, $this->deviceSession($legacyToken)->expires_at->getTimestamp());

        // 50 s after confirm (past the original 10-minute mark) the redeem still works.
        Carbon::setTestNow(Carbon::now()->addSeconds(50));
        [$status] = $this->redeem($token, $verifier);
        $this->assertSame(200, $status);
    }

    // ---- security mail -----------------------------------------------------

    public function test_security_device_signed_in_template_is_registered(): void
    {
        $templates = (new Plugin($this->app))->registerMailTemplates();

        $this->assertContains('golem15.user::mail.security_device_signed_in', $templates);
        $this->assertContains('golem15.user::mail.security_recovery_code_used', $templates);
    }

    public function test_template_carries_the_four_facts_and_no_link_or_token(): void
    {
        $this->assertFileExists($this->mailTemplatePath());
        $tpl = file_get_contents($this->mailTemplatePath());

        $this->assertStringContainsString('subject = "A desktop app signed in to your account"', $tpl);
        foreach (['name', 'device_name', 'ip', 'time'] as $var) {
            $this->assertMatchesRegularExpression('/\{\{\s*' . $var . '\s*\}\}/', $tpl, "missing {{ {$var} }}");
        }

        preg_match_all('/\{\{\s*([a-z_]+)/', $tpl, $m);
        $vars = array_values(array_unique($m[1]));
        sort($vars);
        $this->assertSame(['device_name', 'ip', 'name', 'time'], $vars, 'only the four documented placeholders');
        $this->assertDoesNotMatchRegularExpression('/https?:\/\/|token|url/i', $tpl);
    }

    public function test_redeemed_event_payload_carries_user_session_and_ip(): void
    {
        $user = $this->makeUser();
        $payload = null;
        Event::listen('golem15.user.device.redeemed', function ($u, $s, $ip) use (&$payload) {
            $payload = [$u, $s, $ip];
        });

        [$token, $verifier] = $this->initiateRedeemable(['device_name' => 'WavePath Desktop (Linux)']);
        $this->confirmAs($user, $token);
        [$status] = $this->redeem($token, $verifier);

        $this->assertSame(200, $status);
        $this->assertNotNull($payload);
        $this->assertSame((int) $user->id, (int) $payload[0]->id);
        $this->assertInstanceOf(DeviceAuthSession::class, $payload[1]);
        $this->assertSame('WavePath Desktop (Linux)', $payload[1]->getAttributes()['device_name']);
        $this->assertSame('127.0.0.1', $payload[2]);
    }
}
