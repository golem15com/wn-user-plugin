<?php

namespace Golem15\User\Tests\Unit\DeviceFlow;

require_once __DIR__ . '/DeviceFlowTestCase.php';

use Golem15\User\Models\DeviceAuthSession;
use Markdown;

/**
 * DeviceAuthSession::cleanDisplayName(): the device name comes from the
 * unauthenticated initiate call, so before it is shown (confirm page, security
 * mail rendered as Twig then Markdown) it must not be able to carry a link,
 * markup or invisible characters (107.1 review CR-01 / WR-01).
 */
class DeviceFlowDisplayNameTest extends DeviceFlowTestCase
{
    public function test_plain_names_pass_through_unchanged(): void
    {
        $this->assertSame('WavePath Desktop (Linux)', DeviceAuthSession::cleanDisplayName('WavePath Desktop (Linux)'));
        $this->assertSame("Jakub's laptop", DeviceAuthSession::cleanDisplayName("Jakub's laptop"));
        $this->assertSame('Żółty komputer-2', DeviceAuthSession::cleanDisplayName('Żółty komputer-2'));
    }

    public function test_empty_and_non_string_names_are_null(): void
    {
        $this->assertNull(DeviceAuthSession::cleanDisplayName(null));
        $this->assertNull(DeviceAuthSession::cleanDisplayName(''));
        $this->assertNull(DeviceAuthSession::cleanDisplayName("\t\0 \n"));
        $this->assertNull(DeviceAuthSession::cleanDisplayName('[]<>*_`#!'));
        $this->assertNull(DeviceAuthSession::cleanDisplayName(['x']));
        $this->assertNull(DeviceAuthSession::cleanDisplayName("\xC3\x28")); // invalid UTF-8
    }

    public function test_control_format_and_bidi_characters_are_removed(): void
    {
        // RLO, zero-width space, LRI, PDI, NUL, tab, newline: all removed outright (tab and newline
        // are control characters, as in the wrapper's original cleaning).
        $raw = "Work\u{202E}Lap\u{200B}top \u{2066}x\u{2069}\0\tA\nB";

        $this->assertSame('WorkLaptop xAB', DeviceAuthSession::cleanDisplayName($raw));
    }

    public function test_the_result_is_capped_at_64_characters(): void
    {
        $this->assertSame(str_repeat('Ž', 64), DeviceAuthSession::cleanDisplayName(str_repeat('Ž', 70)));
        $this->assertSame(64, DeviceAuthSession::DISPLAY_NAME_MAX);
    }

    public function test_the_mail_pipeline_does_link_an_uncleaned_name(): void
    {
        // Control: proves the assertions below can fail. Twig escaping alone does not stop it.
        $html = Markdown::parseSafe('Signed in: ' . e('[Secure your account](https://evil.example/x)') . '.');

        $this->assertStringContainsString('<a href="https://evil.example/x"', $html);
    }

    /**
     * @dataProvider hostileNames
     */
    public function test_a_hostile_name_cannot_render_as_a_link_or_markup(string $raw): void
    {
        $clean = (string) DeviceAuthSession::cleanDisplayName($raw);

        $this->assertDoesNotMatchRegularExpression('/[\[\]<>*_`#!|~&:\/.@]/', $clean);

        // The same pipeline as MailManager::render(): Twig escaping, then Markdown.
        $html = Markdown::parseSafe('A desktop app signed in to your account: ' . e($clean) . ', from IP address 203.0.113.5.');
        $this->assertStringNotContainsString('<a', $html);
        $this->assertStringNotContainsString('<img', $html);
        $this->assertStringNotContainsString('<strong', $html);
        $this->assertStringNotContainsString('<em', $html);
        $this->assertStringNotContainsString('<code', $html);
        $this->assertStringNotContainsString('://', $html);
    }

    public static function hostileNames(): array
    {
        return [
            'markdown link' => ['[Secure your account](https://evil.example/x)'],
            'markdown image' => ['![x](https://evil.example/p.png)'],
            'autolink' => ['<https://evil.example/x>'],
            'raw url' => ['https://evil.example/reset'],
            'bare domain' => ['wavepath-security.example'],
            'html' => ['<a href="https://evil.example">x</a>'],
            'emphasis and code' => ['**bold** _it_ `code`'],
            'reference link' => ['[x][1] [1]: https://evil.example'],
            'email' => ['support@evil.example'],
        ];
    }

    // ---- read side (107.1 review WR-01) ---------------------------------------

    public function test_describe_returns_only_the_safe_display_form_of_the_name(): void
    {
        $viewer = $this->makeUser();
        $raw = "\u{202E}[Reset](https://evil.example)\u{200B} <b>now</b>";

        [$token] = $this->initiateRedeemable(['device_name' => $raw]);
        $this->assertSame($raw, $this->deviceSession($token)->getAttributes()['device_name'], 'stored as sent');

        [$status, $body] = $this->describe($token, $viewer);
        $this->assertSame(200, $status);
        $this->assertSame(DeviceAuthSession::cleanDisplayName($raw), $body['data']['device_name']);
        $this->assertSame('Reset(httpsevilexample) bnowb', $body['data']['device_name']);
    }

    public function test_a_redeemable_initiate_rejects_an_over_length_device_name(): void
    {
        [, $challenge] = $this->pkcePair();

        [$status, $body] = $this->initiate(['code_challenge' => $challenge, 'device_name' => str_repeat('a', 256)]);
        $this->assertSame(422, $status);
        $this->assertArrayHasKey('device_name', $body['errors']);

        [$status] = $this->initiate(['code_challenge' => $challenge, 'device_name' => str_repeat('a', 255)]);
        $this->assertSame(200, $status);
    }

    public function test_a_legacy_initiate_still_takes_any_device_name(): void
    {
        // No code_challenge: no new validation and the name is stored verbatim, as before 3.6.0.
        $raw = '[Old](tablet) ' . str_repeat('x', 300);
        [$status, $body] = $this->initiate(['device_name' => $raw]);

        $this->assertSame(200, $status, json_encode($body));
        $this->assertSame($raw, $this->deviceSession($body['data']['token'])->getAttributes()['device_name']);
    }
}
