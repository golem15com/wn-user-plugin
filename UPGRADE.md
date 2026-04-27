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

## AUTH-08: Invitation Email No Longer Contains Plaintext Password

**Severity:** HIGH
**Breaking change:** The invitation email (`golem15.user::mail.invite`) no longer includes the user's password. Instead, it contains a signed activation link that lets the user set their own password. The `password` key has been removed from `getNotificationVars()`.

### What changed

Sending plaintext passwords via email violates OWASP ASVS V2.1.6 and creates security risk (passwords in SMTP logs, email inboxes, relay servers). The `sendInvitation()` method now generates a time-limited signed URL via `URL::temporarySignedRoute()` and passes it as `activation_url` to the email template. The `getNotificationVars()` method no longer includes a `password` key.

### Migration steps

1. **File-based templates:** No action needed -- the updated `invite.htm` ships with this version.

2. **Database-customized templates:** If you have customized the invitation template via the WinterCMS backend (Backend > Settings > Mail templates), you MUST update it:
   - Remove any reference to `{{ password }}` or `{{ password|raw }}` -- this variable is no longer available
   - Add `{{ activation_url }}` where you want the activation link to appear
   - You can also run `php artisan apparatus:mail-reset` to reset all mail templates to their file-based defaults

3. **Custom code consuming `getNotificationVars()`:** If you have code that reads the `password` key from `getNotificationVars()`, it will now return `null`. The password is no longer exposed in notification variables.

4. **Custom invitation flows:** If you call `sendInvitation()` directly or fire the `golem15.user.getNotificationVars` event expecting a `password` key, update your code to use `activation_url` instead.

5. **ResetPassword component requirement:** The activation link redirects to a URL with `?reset={code}`. Your project must have a CMS page with the `ResetPassword` component for the password-set form to render. If your project already supports password reset (most do), no additional setup is needed.

### New behavior

- User receives email with "Set up your account" link
- Link is valid for 72 hours
- Clicking the link redirects to password-set form (via ResetPassword component)
- After 72 hours, the link shows an "expired" message and redirects to site root
- The `&activate=1` query parameter is passed in the redirect URL -- projects can optionally use this to customize messaging (e.g., "Welcome" vs "Reset Password")

### Before / after code

```php
// Before (insecure) -- plaintext password in email
// getNotificationVars() returned: ['name' => ..., 'password' => 'plaintext']
// invite.htm displayed: "Password: {{ password|raw }}"

// After (secure) -- signed activation URL in email
// getNotificationVars() returns: ['name' => ..., 'login' => ...]
// sendInvitation() adds: ['activation_url' => URL::temporarySignedRoute(...)]
// invite.htm displays: "[Set up your account]({{ activation_url }})"
```

### Required env / config changes

None. The signed URL uses the existing `APP_KEY` for HMAC signature.

### Verification

- Send an invitation via the backend and verify the email contains an activation link, not a password.
- Click the activation link and verify you are redirected to a password-set form.
- Wait >72 hours (or modify the expiry temporarily) and verify the link shows an expired message.
