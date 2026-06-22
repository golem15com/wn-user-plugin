<?php namespace Golem15\User\Tests\Security;

use Golem15\User\Tests\UserPluginTestCase;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Security regression tests for HIGH finding USER-002.
 * Each test method is named test_user_NNN_<short_slug> and references
 * the finding in .planning/audit/plugins/golem15/user/FINDINGS.md.
 *
 * Per Phase 7 D-20: PoC tests use HTTP-only + unit fidelity.
 * These tests act as regression locks for the remediated findings and
 * should stay green after the fixes to prevent reintroducing the issues.
 */
#[Group('security')]
class AccessControlTest extends UserPluginTestCase
{
    /**
     * USER-002: Exception message leakage in API controller catch-all handlers.
     *
     * The ApiController's login(), refresh(), register(), and oauthRegisterComplete()
     * methods catch generic \Exception and return $e->getMessage() directly to the
     * API client. Exception messages from database drivers, JWT library internals,
     * or framework code contain internal details.
     *
     * EXPECTATION (post-fix): Catch-all handlers return a generic "Internal server error"
     * for unexpected exceptions, logging the actual error server-side.
     * TODAY (pre-fix): $e->getMessage() is returned directly to API clients.
     * This assertion FAILS because the generic error message pattern is absent.
     *
     * @see .planning/audit/plugins/golem15/user/FINDINGS.md #USER-002
     * @see .planning/audit/DASHBOARD.md #USER-002
     */
    #[Test]
    #[Group('security')]
    public function test_user_002_api_exception_message_leakage(): void
    {
        $source = file_get_contents(
            dirname(__DIR__, 2) . '/controllers/ApiController.php'
        );

        // Extract the login() method catch block area
        // The vulnerability: catch (\Exception $e) { return response()->json(['message' => $e->getMessage()], 500); }
        // A secure implementation would check exception type before returning getMessage()
        // and use a generic message for unexpected exceptions.

        // We look for evidence that the catch blocks differentiate exception types
        // or use a generic message for non-safe exceptions.
        $hasSafeExceptionHandling = (
            str_contains($source, 'Internal server error')
            || str_contains($source, 'An error occurred')
            || str_contains($source, 'generic error')
            || str_contains($source, 'safeExceptionMessage')
        ) || (
            // Or: catches specific exceptions instead of generic \Exception
            !str_contains($source, "catch (\\Exception \$e)")
            && !str_contains($source, "catch (Exception \$ex)")
        );

        $this->assertTrue(
            $hasSafeExceptionHandling,
            'USER-002: ApiController catch-all handlers return $e->getMessage() directly '
            . 'to API clients for generic \\Exception catches. Exception messages from '
            . 'database drivers, JWT internals, or framework code leak table names, column '
            . 'names, SQL fragments, and class paths. '
            . 'Post-fix: replace catch-all \\Exception handlers with specific exception types '
            . 'that have safe messages, and return generic "Internal server error" for '
            . 'unexpected exceptions.'
        );
    }
}
