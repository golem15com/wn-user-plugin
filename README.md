![User](assets/images/hero.png)

# Golem15.User

Enhanced front-end user management for Winter CMS. Extends the core user system with JWT API authentication, OAuth social login (Google, Facebook, GitHub), GDPR compliance (consent tracking, data export, account deletion), family accounts with PIN-based child authentication, QR code device authorization, and mail blocking.

## Features

- **User Registration & Login** — Email or username-based authentication with throttling
- **JWT API Authentication** — Stateless token-based auth for mobile/SPA clients
- **OAuth Social Login** — Google, Facebook, GitHub via Laravel Socialite
- **GDPR Compliance** — Consent tracking, audit trail, cookie consent, data export, account deletion with grace period
- **Family Accounts** — Parent-child relationships with role switching
- **PIN Authentication** — 4-digit PIN login for child accounts with lockout protection
- **Device Authorization** — QR code-based new device login flow
- **Cookie Consent** — Configurable banner with category-based preferences
- **Mail Blocking** — Per-user mail template blocking
- **Guest Users** — Deferred registration with guest-to-user conversion
- **User Groups** — Group-based permissions and categorization
- **Session Management** — Page/route access control, concurrent session prevention
- **Account Activation** — Automatic, user email, or admin approval modes
- **User Impersonation** — Backend admins can impersonate users
- **Activity Tracking** — Last seen, last login, IP address recording
- **Soft Delete** — Deactivation with restoration support

## Requirements

This plugin requires the [Snowboard framework](https://wintercms.com/docs/v1.2/docs/snowboard/introduction) or the [Ajax Framework](https://wintercms.com/docs/v1.2/docs/ajax/introduction) in your layout.

### Composer Dependencies

- `php-open-source-saver/jwt-auth` — JWT token generation/validation
- `laravel/socialite` — OAuth provider integration
- `google/recaptcha` — reCAPTCHA support
- `pragmarx/google2fa` — Two-factor authentication (prepared)
- `bacon/bacon-qr-code` — QR code generation
- `firebase/php-jwt` — JWT encoding/decoding

---

## Components

### Session

Injects the `user` variable into every page and provides access control and logout.

```ini
[session]
security = "user"
redirect = "home"
```

The `security` property can be `user` (authenticated only), `guest` (guests only), or `all` (no restriction).

```twig
{% if user %}
    <p>Hello {{ user.name }}</p>
{% else %}
    <p>Nobody is logged in</p>
{% endif %}
```

**Signing out:**

```html
<a href="javascript:;" data-request="onLogout" data-request-data="redirect: '/good-bye'">Sign out</a>
```

### Account

Provides registration, sign in, profile editing, and activation forms:

```ini
[account]
redirect = "home"
paramCode = "code"
==
{% component 'account' %}
```

Displays a sign in / registration form for guests, or a profile update form for authenticated users. Supports OAuth provider buttons (Google, Facebook, GitHub) and guest user conversion.

### ResetPassword

Password reset workflow with email verification:

```ini
[resetPassword]
paramCode = "code"
==
{% component 'resetPassword' %}
```

### SocialAuth

OAuth login, registration, and account linking:

```ini
[socialAuth]
redirectAfterAuth = "home"
redirectAfterLink = "account"
==
{% component 'socialAuth' %}
```

**Supported providers:** Google, Facebook, GitHub

**Handlers:** `onRedirectToProvider`, `onOAuthCallback`, `onLinkAccount`, `onUnlinkAccount`

### DeviceAuth

QR code-based device authorization for new device login:

```ini
[deviceAuth]
token = "{{ :token }}"
==
{% component 'deviceAuth' %}
```

**Handlers:** `onGenerateQR`, `onConfirmAuth`, `onApproveAuth`, `onPollStatus`, `onRevokeDevice`

The flow: new device initiates auth → generates QR code with short code (XXXX-XXXX format) → authorized device scans/confirms → new device polls for confirmation → login granted.

### CookieConsent

GDPR cookie consent banner with granular preferences:

```ini
[cookieConsent]
mode = "smart"
position = "bottom"
==
{% component 'cookieConsent' %}
```

**Modes:** `disabled`, `always`, `smart` (show when consent needed)

**Cookie categories:** essential (always required), analytics, marketing

**Handlers:** `onAcceptAll`, `onRejectOptional`, `onSavePreferences`

---

## Auth Facade

```php
use Golem15\User\Facades\Auth;

// Register a user
$user = Auth::register([
    'name' => 'Some User',
    'email' => 'some@website.tld',
    'password' => 'changeme',
    'password_confirmation' => 'changeme',
]);

// Auto-activate on registration
$user = Auth::register([...], true);

// Check if signed in
$loggedIn = Auth::check();

// Get current user
$user = Auth::getUser();

// Authenticate by credentials
$user = Auth::authenticate([
    'login' => post('login'),
    'password' => post('password'),
]);

// Sign in as a specific user (second arg = remember)
Auth::login($user, true);

// Look up user by login name
$user = Auth::findUserByLogin('some@email.tld');

// Register a guest user
$user = Auth::registerGuest(['email' => 'person@acme.tld']);
```

---

## JWT API Authentication

Stateless token-based authentication for API clients. Tokens are issued on login and must be included in subsequent requests via the `Authorization: Bearer <token>` header.

### Configuration

JWT settings are in `config/jwt.php`:
- **TTL:** 60 minutes (default, configurable via `JWT_TTL` env)
- **Refresh TTL:** 20,160 minutes (2 weeks)
- **Algorithm:** HS256
- **Blacklist:** Enabled with grace period

### API Endpoints

All endpoints prefixed with `/_user/api/v1`. Rate limited to 120 requests/minute.

#### Authentication

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/login` | No | Login, returns JWT token + user data |
| `POST` | `/logout` | JWT | Invalidate token |
| `GET` | `/fetch` | JWT | Get current user data |
| `POST` | `/refresh` | JWT | Refresh expired token |
| `POST` | `/register` | No | Register new user, returns JWT token |
| `POST` | `/activate` | JWT | Activate account with code |
| `POST` | `/forgot-password` | No | Request password reset |
| `POST` | `/reset-password` | No | Reset password with code |

#### PIN Authentication (10 req/min rate limit)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/pin-login` | No | Login child with 4-digit PIN |
| `POST` | `/verify-pin` | JWT | Verify PIN for authenticated user |
| `POST` | `/verify-family-member-pin` | JWT | Verify PIN for family member |

#### OAuth

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/oauth-providers` | No | List enabled OAuth providers |

#### Device Management

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/devices` | JWT | List active devices |
| `DELETE` | `/devices/{id}` | JWT | Revoke a device session |
| `POST` | `/devices/authorize` | JWT | Authorize a new device |
| `POST` | `/devices/initiate` | No | Start QR auth flow |
| `GET` | `/devices/status/{token}` | No | Poll device auth status |

#### Batch User Info

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/user/batch?ids=1,2,3` | No | Get multiple users' data |

### Middleware

Protect routes with JWT authentication:

```php
Route::group(['middleware' => 'jwt.auth'], function () {
    // Authenticated routes
});
```

Or use the session-based middleware:

```php
Route::group(['middleware' => 'Golem15\User\Classes\AuthMiddleware'], function () {
    // Authenticated routes
});
```

---

## OAuth / Social Login

Supports Google, Facebook, and GitHub via Laravel Socialite.

### Configuration

Set credentials in `.env`:

```env
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=https://yoursite.com/oauth/google/callback

FACEBOOK_CLIENT_ID=your-client-id
FACEBOOK_CLIENT_SECRET=your-client-secret
FACEBOOK_REDIRECT_URI=https://yoursite.com/oauth/facebook/callback

GITHUB_CLIENT_ID=your-client-id
GITHUB_CLIENT_SECRET=your-client-secret
GITHUB_REDIRECT_URI=https://yoursite.com/oauth/github/callback
```

### OAuth Routes

| Method | URL | Description |
|--------|-----|-------------|
| `GET` | `/oauth/{provider}` | Redirect to provider |
| `GET` | `/oauth/{provider}/callback` | Handle callback |

### Features

- New user registration via OAuth
- Login for existing OAuth-linked users
- Account linking (add OAuth to existing account)
- Account unlinking
- Encrypted token storage (access token, refresh token)
- Token expiration tracking
- Provider profile data storage

---

## Family Accounts

Parent-child account relationships with role-based access.

### FamilyAuth Helper

```php
use Golem15\User\Facades\FamilyAuth;

$user = FamilyAuth::getUser();       // Active user (role session or auth)
$authUser = FamilyAuth::getAuthUser(); // Authenticated user (always the parent)
$role = FamilyAuth::getRole();        // 'parent' or 'child'

FamilyAuth::isParent();    // true if acting as parent
FamilyAuth::isChild();     // true if acting as child
FamilyAuth::isRoleSwitched(); // true if role differs from auth
FamilyAuth::check();       // is authenticated?
```

### PIN System

Children can authenticate with a 4-digit PIN:
- PIN lockout after failed attempts (configurable)
- PIN recovery codes
- PIN-less children require an authenticated parent in the same family
- Generic error messages prevent user enumeration

---

## GDPR Compliance

### Consent Tracking

```php
// Record user consent
$user->recordConsent('terms', '2024-12-17', $ipAddress, $userAgent);
$user->recordConsent('privacy', '2024-12-17', $ipAddress, $userAgent);

// Check if user has current consent
$user->hasCurrentConsent(); // checks against config policy versions

// Withdraw marketing consent
$user->withdrawMarketingConsent();
```

### Consent Audit Trail

All consent actions are recorded in the `golem15_user_consent_audit` table with user agent, IP address, policy version, and timestamp. Retention: 7 years (configurable).

### Data Export

```php
$data = $user->exportPersonalData();
// Returns JSON with all user data per GDPR Articles 15 & 20
```

### Account Deletion

```php
// Request deletion (starts 30-day grace period)
$user->requestDeletion('I no longer need this account');

// Cancel pending deletion
$user->cancelDeletion();

// Hard delete (cascades: avatar, device sessions, consent audits, etc.)
$user->hardDelete();
```

The `user:process-scheduled-deletions` command should run daily to process expired grace periods.

### Configuration

GDPR settings in `config/gdpr.php`:
- Policy versions (terms, privacy)
- Cookie consent categories and versions
- Deletion grace period (default: 30 days)
- Data export format and filename pattern
- Audit retention period
- Data controller contact information
- Feature toggles (consent tracking, data export, account deletion, consent audit)

---

## Guest Users

```php
// Create a guest user (deferred registration)
$user = Auth::registerGuest(['email' => 'person@acme.tld']);

// Later, register with the same email (inherits guest account)
$user = Auth::register([
    'email' => 'person@acme.tld',
    'password' => 'changeme',
    'password_confirmation' => 'changeme',
]);

// Or convert manually (sends invitation email with random password)
$user->convertToRegistered();

// Convert without notification
$user->convertToRegistered(false);
```

---

## Mail Blocking

Users can block specific mail templates from being sent to them. The `block_mail` checkbox in the backend blocks all outgoing mail except password reset.

```php
use Golem15\User\Models\MailBlocker;

MailBlocker::addBlock('golem15.user::mail.welcome', $user);
MailBlocker::removeBlock('golem15.user::mail.welcome', $user);
MailBlocker::blockAll($user);
MailBlocker::unblockAll($user);
```

Safe templates (e.g., password restore) cannot be blocked.

---

## Plugin Settings

Navigate to **Settings > Users > User Settings**.

### Registration

- **Allow user registration** — Enable/disable public registration
- **Registration throttle** — Max 3 registrations per 60 minutes per IP

### Activation

- **Automatic** — Activated on registration (default)
- **User** — Activation via email confirmation link
- **Administrator** — Manual activation by admin

### Sign In

- **Login attribute** — Email (default) or Username
- **Throttle attempts** — Suspend after 5 failed attempts for 15 minutes
- **Prevent concurrent sessions** — One active session per user
- **Remember login** — Always, never, or ask the user

### Password

Minimum password length configurable in `config/config.php` (default: 8).

---

## Events

| Event | Description |
|-------|-------------|
| `golem15.user.beforeRegister` | Before registration (passed `$data` by reference) |
| `golem15.user.register` | After successful registration (passed `$user`, `$data`) |
| `golem15.user.beforeAuthenticate` | Before authentication attempt |
| `golem15.user.login` | After successful sign in |
| `golem15.user.logout` | After sign out |
| `golem15.user.activate` | After email activation |
| `golem15.user.deactivate` | After account deactivation (soft delete) |
| `golem15.user.reactivate` | After account reactivation |
| `golem15.user.getNotificationVars` | When sending notification (add extra template vars) |
| `golem15.user.view.extendListToolbar` | Extend user list toolbar in backend |
| `golem15.user.view.extendPreviewToolbar` | Extend user preview toolbar in backend |

```php
Event::listen('golem15.user.register', function ($user, $data) {
    // Custom post-registration logic
});
```

---

## Mail Templates

| Template | Description |
|----------|-------------|
| `golem15.user::mail.activate` | Account activation link |
| `golem15.user::mail.welcome` | Welcome message after activation |
| `golem15.user::mail.restore` | Password reset link |
| `golem15.user::mail.new_user` | New user notification (admin) |
| `golem15.user::mail.reactivate` | Account reactivation |
| `golem15.user::mail.invite` | Guest-to-user invitation |

---

## Console Commands

| Command | Description |
|---------|-------------|
| `user:process-scheduled-deletions` | Process users whose GDPR deletion grace period has expired |

Should be scheduled to run daily:

```bash
0 2 * * * php /path/to/winter/artisan user:process-scheduled-deletions
```

---

## Permissions

| Permission | Description |
|------------|-------------|
| `golem15.users.access_users` | Access users list |
| `golem15.users.access_groups` | Access user groups |
| `golem15.users.access_settings` | Access plugin settings |
| `golem15.users.impersonate_user` | Impersonate users |

---

## Localization

Ships with translations for:
- English (en)
- Polish (pl)
- French (fr)

---

## Overriding Functionality

Override component handlers in page code:

```php
function onSignin()
{
    try {
        return $this->account->onSignin();
    } catch (Exception $ex) {
        Log::error($ex);
    }
}
```

---

## License

MIT
