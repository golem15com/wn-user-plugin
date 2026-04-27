# Upgrade guide

- [Upgrading to 1.1 from 1.0](#upgrade-1.1)
- [Upgrading to 1.4 from 1.3](#upgrade-1.4)

<a name="upgrade-1.1"></a>
## Upgrading To 1.1

The User plugin has been split apart in to smaller more manageable plugins. These fields are no longer provided by the User plugin: `company`, `phone`, `street_addr`, `city`, `zip`, `country`, `state`. This is a non-destructive upgrade so the columns will remain in the database untouched.

Country and State models have been removed and can be replaced by installing the plugin **Winter.Location**. The remaining profiles fields can be replaced by installing the plugin **Winter.UserPlus**.

In short, to retain the old functionaliy simply install the following plugins:

- Winter.Location
- Winter.UserPlus

<a name="upgrade-1.4"></a>
## Upgrading To 1.4

The Notifications tab in User settings has been removed. This feature has been replaced by the [Notify plugin](https://github.com/wintercms/wn-notify-plugin). How to replace this feature:

1. Install the `Winter.Notify` plugin
1. Navigate to Settings > Notification rules
1. Click **New notification** rule
1. Select User > **Activated**
1. Click **Add action**
1. Select **Compose a mail message**
1. Select **User email address** for the **Send to field**
1. Here you may select the **Mail template** previously defined in the user settings.
1. Click **Save**

---

# Security Upgrade Guide (Phase 7 Audit)

**Projected version bump:** MAJOR
**Security audit phase:** 7 (Cross-Plugin Analysis & Remediation Planning)
**Generated:** 2026-04-27

> Breaking changes from the Golem15 security audit.
> Each section corresponds to a finding in .planning/audit/plugins/golem15/user/FINDINGS.md.

## USER-001: OAuth tokens in User $fillable allow mass-assignment of encrypted credentials

**Severity:** CRITICAL
**Breaking change:** OAuth-related fields have been removed from the User model's `$fillable` array; any code that sets OAuth fields via mass-assignment (`fill()`, `create()`, or `update()`) will have those fields silently ignored.

### What changed

The User model's `$fillable` array previously included `oauth_access_token`, `oauth_refresh_token`, `oauth_token_expires_at`, `oauth_provider`, `oauth_provider_id`, `oauth_profile_data`, and `oauth_linked_at`. This allowed any code path that passed user input to `Auth::register($data)` or `$user->fill($data)` to set these fields directly, bypassing the encryption and validation in `linkOAuthProvider()`. The fix removes all OAuth fields from `$fillable`. OAuth credentials must now be set exclusively through the `linkOAuthProvider()` method, which handles encryption and duplicate-provider validation.

### Migration steps

1. Audit any code that calls `$user->fill()`, `User::create()`, or `Auth::register()` with arrays containing `oauth_provider`, `oauth_provider_id`, `oauth_access_token`, `oauth_refresh_token`, or related fields. These fields will now be silently ignored during mass-assignment.
2. Replace direct mass-assignment of OAuth fields with calls to `$user->linkOAuthProvider($provider, $socialiteUser)`.
3. If you have custom OAuth integration code that sets tokens via `$user->update(['oauth_access_token' => ...])`, refactor to use the model's `linkOAuthProvider()` method or explicit attribute setters that handle encryption.
4. Review API registration endpoints that pass `$request->all()` to `Auth::register()` -- ensure the request input is filtered to exclude OAuth fields.

### Before / after code

```php
// Before (vulnerable) -- OAuth fields mass-assignable, bypassing encryption
$user = Auth::register([
    'name' => $data['name'],
    'email' => $data['email'],
    'password' => $data['password'],
    'oauth_provider' => 'google',           // accepted, stored unencrypted
    'oauth_provider_id' => 'ATTACKER_ID',   // accepted, enables account takeover
    'oauth_access_token' => 'PLAINTEXT',    // accepted, bypasses encrypt()
]);

// After (secure) -- OAuth fields excluded from $fillable
$user = Auth::register([
    'name' => $data['name'],
    'email' => $data['email'],
    'password' => $data['password'],
    // oauth_* fields silently ignored
]);
// Set OAuth credentials through the proper API:
$user->linkOAuthProvider('google', $socialiteUser); // handles encryption + validation
```

### Required env / config changes

None.

### Composer constraint changes (if any)

Update `golem15/user` to `^2.0` in downstream composer.json.

### Verification

- Run `vendor/bin/phpunit --configuration plugins/golem15/user/phpunit.xml --group security` -- `test_user_001_oauth_tokens_mass_assignable` should PASS after fix.
- Verify that OAuth login/registration flow still works correctly (social auth via Google/Facebook/GitHub).
- Verify that `linkOAuthProvider()` still correctly encrypts and stores OAuth tokens.
- Attempt to register a user with `oauth_provider` in the POST body and verify it is ignored.
