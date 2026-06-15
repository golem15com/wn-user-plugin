<?php namespace Golem15\User\Tests\Security;

use Golem15\User\Tests\UserPluginTestCase;

/**
 * Regression locks for the profile-authorization event seams introduced when
 * QuestStream family logic was decoupled out of the User plugin (ticket
 * ajoyc8tt, PR #2). These authorization decisions are plugin-defined and MUST
 * be fail-safe: when no listener is registered the QuestStream-specific
 * PIN-login / profile-switch flows are denied, never wide open.
 *
 * Flagged by Copilot review on PR #2:
 * https://github.com/golem15com/wn-user-plugin/pull/2
 *
 * @group security
 */
class ProfileAuthorizationSeamTest extends UserPluginTestCase
{
    private function apiControllerSource(): string
    {
        return file_get_contents(dirname(__DIR__, 2) . '/controllers/ApiController.php');
    }

    /**
     * The authorization seams must grant access only on an explicit boolean
     * true from a listener. A permissive default (treating null / "no listener"
     * as allowed) would let any authenticated user drive the PIN-login and
     * profile-switch flows in a project that never registers a listener.
     *
     * @test
     * @group security
     */
    public function test_profile_authorization_seams_are_fail_safe(): void
    {
        $src = $this->apiControllerSource();

        // PIN-login eligibility: deny unless explicitly eligible.
        $this->assertStringContainsString(
            '$pinLoginEligible !== true',
            $src,
            'pinLogin must deny when the eligibility listener does not explicitly return true.'
        );

        // Same-family / profile-access authorization (two call sites: pinLogin
        // PIN-less path and verifyFamilyMemberPin).
        $this->assertSame(
            2,
            substr_count($src, '$authorized !== true'),
            'Both authorizeProfileAccess checks must deny unless a listener returns true.'
        );

        // canAuthorizeProfiles: only an explicit true makes a user an authority.
        $this->assertStringContainsString(
            '$canAuthorize === true',
            $src,
            'getAuthenticatedAuthority must treat a user as an authority only on explicit true.'
        );

        // Token issuance on profile switch (two call sites): mint only on true.
        $this->assertSame(
            2,
            substr_count($src, 'if ($issuesToken === true)'),
            'Profile-switch token issuance must require an explicit true.'
        );

        // No permissive remnants of the old default (null treated as allowed).
        $this->assertStringNotContainsString(
            '$issuesToken === null',
            $src,
            'Token issuance must not fall back to issuing a token when no listener is registered.'
        );
    }

    /**
     * With no listeners registered, the seam events resolve to null in halt
     * mode, which the fail-safe checks treat as "deny". This documents the
     * standalone (no-QuestStream) default: the QuestStream-specific flows are
     * off rather than wide open.
     *
     * @test
     * @group security
     */
    public function test_seam_events_default_to_null_without_listeners(): void
    {
        $events = [
            'golem15.user.pinLoginEligible',
            'golem15.user.canAuthorizeProfiles',
            'golem15.user.authorizeProfileAccess',
            'golem15.user.profileSwitchIssuesToken',
        ];

        foreach ($events as $event) {
            $this->assertNull(
                \Event::fire($event, [null, null], true),
                "Seam {$event} must resolve to null when no listener is registered, "
                . 'so the fail-safe controller checks deny by default.'
            );
        }
    }

    /**
     * The JWT-authority helper was renamed away from the parent/child wording
     * because parent semantics are now plugin-defined. Lock the rename so the
     * misleading name does not creep back.
     *
     * @test
     * @group security
     */
    public function test_authority_helper_is_not_named_after_parent(): void
    {
        $src = $this->apiControllerSource();

        $this->assertStringContainsString('private function getAuthenticatedAuthority(', $src);
        $this->assertStringNotContainsString('getAuthenticatedParent', $src);
    }
}
