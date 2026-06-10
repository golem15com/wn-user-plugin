<?php

namespace Golem15\User\Components;

use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Cms\Classes\ComponentBase;
use Golem15\User\Facades\Auth;
use Golem15\User\Models\DeviceAuthSession;
use Golem15\User\Models\User;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Session;
use Winter\Storm\Exception\ApplicationException;

/**
 * DeviceAuth Component
 *
 * Handles QR code-based device authorization flow.
 * New devices scan QR code, poll for confirmation, then auto-login.
 */
class DeviceAuth extends ComponentBase
{
    public $token;
    public $session;

    /**
     * Component details
     */
    public function componentDetails()
    {
        return [
            'name'        => 'Device Authorization',
            'description' => 'QR code-based device authorization'
        ];
    }

    /**
     * Component properties
     */
    public function defineProperties()
    {
        return [
            'token' => [
                'title' => 'Auth Token',
                'description' => 'Device authorization token from QR code',
                'default' => '{{ :token }}',
                'type' => 'string',
            ],
        ];
    }

    /**
     * Run on component initialization
     */
    public function onRun()
    {
        $this->token = $this->property('token');

        if ($this->token) {
            $this->session = $this->page['session'] = DeviceAuthSession::findValidToken($this->token);

            if (!$this->session) {
                $this->page['error'] = 'Invalid or expired authorization token.';
            }
        }
    }

    /**
     * Generate QR code for device authorization
     * Called from parent profile or other authenticated context
     */
    public function onGenerateQR()
    {
        $user = Auth::getUser();

        if (!$user) {
            throw new ApplicationException('You must be logged in to generate an authorization QR code.');
        }

        // Rate limiting: max 5 QR codes per hour
        $recentCount = DeviceAuthSession::where('user_id', $user->id)
            ->where('created_at', '>=', now()->subHour())
            ->count();

        if ($recentCount >= 5) {
            throw new ApplicationException('You have generated too many authorization codes. Please wait and try again.');
        }

        // Generate authorization session
        $authSession = DeviceAuthSession::generate($user, [
            'ip' => request()->ip(),
            'user_agent' => request()->userAgent(),
        ], 5); // 5 minutes expiry

        // Generate QR code (SVG format)
        $renderer = new ImageRenderer(
            new RendererStyle(400, 0), // 400px size, no margin (we'll add it in CSS)
            new SvgImageBackEnd()
        );
        $writer = new Writer($renderer);
        $qrCodeSvg = $writer->writeString($authSession->getAuthUrl());

        Log::info('QuestStream: Device authorization QR code generated', [
            'user_id' => $user->id,
            'token' => $authSession->token,
            'expires_at' => $authSession->expires_at->toDateTimeString(),
        ]);

        return [
            'qr_code' => $qrCodeSvg,
            'token' => $authSession->token,
            'expires_at' => $authSession->expires_at->toDateTimeString(),
            'expires_in_seconds' => $authSession->expires_at->diffInSeconds(now()),
            'auth_url' => $authSession->getAuthUrl(),
        ];
    }

    /**
     * Generate QR code for NEW DEVICE (unauthenticated)
     * This is the reversed flow: new device generates QR, parent scans it
     */
    public function onGenerateDeviceQR()
    {
        // This endpoint is called by UNAUTHENTICATED devices
        // We need to create a "pending" auth session without a user_id yet
        // The parent will scan this QR and link it to their account

        // Get device info from request
        $deviceInfo = post('device_info', []);

        // Create a temporary user record or use a placeholder
        // Actually, we need to know WHICH user this is for...
        // The QR code needs to encode: "I want to log in, please authorize me"

        // WAIT - we need to rethink this. The new device doesn't know which user
        // it wants to log in as. The parent scanning the QR is the one who will
        // authorize their own account on this new device.

        // So the flow should be:
        // 1. New device generates a temporary token (not linked to any user yet)
        // 2. Parent scans QR on their authenticated device
        // 3. Parent sees: "Authorize your account on this new device?"
        // 4. Parent confirms
        // 5. Token gets linked to parent's user_id
        // 6. New device polls and sees confirmation, logs in as that user

        // Let's create a "anonymous" auth session that will be claimed later
        // We'll use user_id = 0 or null as a placeholder

        // Rate limiting by IP to prevent abuse
        $recentCount = DeviceAuthSession::where('device_ip', request()->ip())
            ->where('created_at', '>=', now()->subHour())
            ->whereNull('user_id') // Only count unclaimed sessions
            ->count();

        if ($recentCount >= 10) {
            throw new ApplicationException('Too many authorization requests from this IP. Please wait and try again.');
        }

        // Generate unique short code before creation (to avoid second save() which corrupts expires_at)
        do {
            $characters = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
            $code = '';
            for ($i = 0; $i < 8; $i++) {
                $code .= $characters[random_int(0, strlen($characters) - 1)];
            }
            $shortCode = substr($code, 0, 4) . '-' . substr($code, 4, 4);
        } while (DeviceAuthSession::where('short_code', $shortCode)->exists());

        // Create temporary auth session without user (with all data including short_code)
        $authSession = DeviceAuthSession::create([
            'token' => \Illuminate\Support\Str::random(64),
            'short_code' => $shortCode,
            'user_id' => null, // Will be set when parent scans
            'status' => 'pending',
            'expires_at' => now()->addMinutes(5),
            'device_ip' => request()->ip(),
            'device_user_agent' => $deviceInfo['user_agent'] ?? request()->userAgent(),
            'device_name' => $deviceInfo['device_name'] ?? null,
        ]);

        // Generate QR code (SVG format)
        $renderer = new ImageRenderer(
            new RendererStyle(400, 0),
            new SvgImageBackEnd()
        );
        $writer = new Writer($renderer);
        $qrCodeSvg = $writer->writeString($authSession->getAuthUrl());

        Log::info('QuestStream: Device QR code generated (unauthenticated)', [
            'token' => $authSession->token,
            'short_code' => $authSession->short_code,
            'device_ip' => $authSession->device_ip,
            'expires_at' => $authSession->expires_at->toDateTimeString(),
        ]);

        return [
            'qr_code' => $qrCodeSvg,
            'token' => $authSession->token,
            'short_code' => $authSession->short_code,
            'expires_at' => $authSession->expires_at->toDateTimeString(),
            'expires_in_seconds' => $authSession->expires_at->diffInSeconds(now()),
            'auth_url' => $authSession->getAuthUrl(),
        ];
    }

    /**
     * Check authorization status (polling endpoint for new device)
     * Called by JavaScript on new device every 2 seconds
     * This is for the reversed flow where device is waiting for parent to scan
     */
    public function onCheckAuthStatus()
    {
        $token = post('token');

        if (!$token) {
            return ['status' => 'error', 'message' => 'Token is required'];
        }

        $authSession = DeviceAuthSession::where('token', $token)->first();

        if (!$authSession) {
            return ['status' => 'expired', 'message' => 'Authorization token not found'];
        }

        // Check if expired
        if ($authSession->expires_at < now()) {
            $authSession->status = 'expired';
            $authSession->save();
            return ['status' => 'expired', 'message' => 'Authorization token has expired'];
        }

        // Check if confirmed
        if ($authSession->isConfirmed() && $authSession->user_id) {
            // Parent has scanned and confirmed! Log this device in
            $user = $authSession->user;

            // Log the user in
            Auth::login($user, true); // true = remember me

            // Get Winter session ID
            $sessionId = Session::getId();

            // Mark session as used
            $authSession->markAsUsed($sessionId);

            Log::info('QuestStream: Device authorization completed via QR scan', [
                'user_id' => $user->id,
                'token' => $authSession->token,
                'session_id' => $sessionId,
                'device_ip' => $authSession->device_ip,
            ]);

            return [
                'status' => 'confirmed',
                'message' => 'Authorization confirmed! Redirecting...',
                'user_name' => $user->name,
            ];
        }

        // Still pending
        return [
            'status' => $authSession->status,
            'message' => 'Waiting for authorization...',
            'expires_in_seconds' => max(0, $authSession->expires_at->diffInSeconds(now())),
        ];
    }

    /**
     * Legacy polling method (kept for backward compatibility)
     */
    public function onCheckStatus()
    {
        return $this->onCheckAuthStatus();
    }

    /**
     * Confirm authorization (parent clicks confirm on their logged-in device)
     */
    public function onConfirmAuthorization()
    {
        $token = post('token');
        $user = Auth::getUser();

        if (!$user) {
            throw new ApplicationException('You must be logged in to confirm authorization.');
        }

        if (!$token) {
            throw new ApplicationException('Token is required');
        }

        $authSession = DeviceAuthSession::findValidToken($token);

        if (!$authSession) {
            throw new ApplicationException('Invalid or expired authorization token.');
        }

        // Verify this session belongs to the logged-in user
        if ($authSession->user_id !== $user->id) {
            throw new ApplicationException('This authorization request is not for your account.');
        }

        // Confirm the authorization
        $authSession->confirm(request()->ip());

        Log::info('QuestStream: Device authorization confirmed by parent', [
            'user_id' => $user->id,
            'token' => $authSession->token,
            'device_ip' => $authSession->device_ip,
            'auth_ip' => request()->ip(),
        ]);

        return [
            'success' => true,
            'message' => 'Device authorized successfully! The new device can now complete login.',
        ];
    }

    /**
     * Get list of authorized devices for current user
     */
    public function onListDevices()
    {
        $user = Auth::getUser();

        if (!$user) {
            throw new ApplicationException('You must be logged in.');
        }

        $devices = DeviceAuthSession::getActiveDevices($user->id);

        return [
            'devices' => $devices->map(function ($device) {
                return [
                    'id' => $device->id,
                    'device_name' => $device->device_name_attribute,
                    'device_info' => $device->device_info_attribute,
                    'device_ip' => $device->device_ip,
                    'authorized_at' => $device->confirmed_at?->diffForHumans(),
                    'last_activity' => $device->last_activity_at?->diffForHumans(),
                    'is_current' => Session::getId() === $device->session_id,
                ];
            }),
        ];
    }

    /**
     * Revoke a device authorization
     */
    public function onRevokeDevice()
    {
        $deviceId = post('device_id');
        $user = Auth::getUser();

        if (!$user) {
            throw new ApplicationException('You must be logged in.');
        }

        if (!$deviceId) {
            throw new ApplicationException('Device ID is required.');
        }

        $device = DeviceAuthSession::find($deviceId);

        if (!$device || $device->user_id !== $user->id) {
            throw new ApplicationException('Device not found or does not belong to you.');
        }

        // Don't allow revoking current session
        if (Session::getId() === $device->session_id) {
            throw new ApplicationException('You cannot revoke your current device. Please use another device to revoke this one.');
        }

        $device->revoke();

        // NOTE(g15-starter): optional hard-destroy of the session row on device logout is
        // deferred (current behavior unchanged). Tracked — see G15 Starter g15office task.
        // This requires access to session storage

        Log::info('QuestStream: Device authorization revoked', [
            'user_id' => $user->id,
            'device_id' => $deviceId,
            'device_info' => $device->device_info_attribute,
        ]);

        return [
            'success' => true,
            'message' => 'Device access revoked successfully.',
        ];
    }
}
