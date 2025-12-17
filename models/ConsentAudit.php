<?php namespace Golem15\User\Models;

use Model;

/**
 * ConsentAudit Model
 *
 * Tracks all consent-related actions for GDPR compliance.
 * Provides complete audit trail of when users granted, withdrew, or updated their consent.
 *
 * GDPR Article 7(1): "Where processing is based on consent, the controller shall
 * be able to demonstrate that the data subject has consented to processing of
 * his or her personal data."
 *
 * @property int $id
 * @property int $user_id
 * @property string $consent_type (terms|privacy|marketing)
 * @property string $action (granted|withdrawn|updated)
 * @property string $policy_version
 * @property string $ip_address
 * @property string $user_agent
 * @property array $metadata
 * @property \Carbon\Carbon $created_at
 * @property \Carbon\Carbon $updated_at
 *
 * @property User $user
 */
class ConsentAudit extends Model
{
    /**
     * @var string The database table used by the model.
     */
    public $table = 'golem15_user_consent_audit';

    /**
     * @var array Guarded fields
     */
    protected $guarded = ['*'];

    /**
     * @var array Fillable fields
     */
    protected $fillable = [
        'user_id',
        'consent_type',
        'action',
        'policy_version',
        'ip_address',
        'user_agent',
        'metadata',
    ];

    /**
     * @var array Attributes to cast to native types
     */
    protected $casts = [
        'metadata' => 'array',
    ];

    /**
     * @var array Validation rules
     */
    public $rules = [
        'user_id' => 'required|integer|exists:users,id',
        'consent_type' => 'required|in:terms,privacy,marketing',
        'action' => 'required|in:granted,withdrawn,updated',
        'policy_version' => 'nullable|string|max:20',
        'ip_address' => 'nullable|string|max:45',
        'user_agent' => 'nullable|string',
    ];

    /**
     * @var array Relations
     */
    public $belongsTo = [
        'user' => [User::class],
    ];

    /**
     * Consent types
     */
    const CONSENT_TYPE_TERMS = 'terms';
    const CONSENT_TYPE_PRIVACY = 'privacy';
    const CONSENT_TYPE_MARKETING = 'marketing';

    /**
     * Actions
     */
    const ACTION_GRANTED = 'granted';
    const ACTION_WITHDRAWN = 'withdrawn';
    const ACTION_UPDATED = 'updated';

    /**
     * Get consent type display name
     *
     * @return string
     */
    public function getConsentTypeNameAttribute()
    {
        $types = [
            self::CONSENT_TYPE_TERMS => 'Terms of Use',
            self::CONSENT_TYPE_PRIVACY => 'Privacy Policy',
            self::CONSENT_TYPE_MARKETING => 'Marketing Communications',
        ];

        return $types[$this->consent_type] ?? $this->consent_type;
    }

    /**
     * Get action display name
     *
     * @return string
     */
    public function getActionNameAttribute()
    {
        $actions = [
            self::ACTION_GRANTED => 'Granted',
            self::ACTION_WITHDRAWN => 'Withdrawn',
            self::ACTION_UPDATED => 'Updated',
        ];

        return $actions[$this->action] ?? $this->action;
    }

    /**
     * Scope: Get audit records for a specific user
     *
     * @param $query
     * @param int $userId
     * @return mixed
     */
    public function scopeForUser($query, $userId)
    {
        return $query->where('user_id', $userId);
    }

    /**
     * Scope: Get audit records for a specific consent type
     *
     * @param $query
     * @param string $consentType
     * @return mixed
     */
    public function scopeForType($query, $consentType)
    {
        return $query->where('consent_type', $consentType);
    }

    /**
     * Scope: Get recent audit records
     *
     * @param $query
     * @param int $days
     * @return mixed
     */
    public function scopeRecent($query, $days = 30)
    {
        return $query->where('created_at', '>=', now()->subDays($days));
    }

    /**
     * Scope: Get audit records for a specific action
     *
     * @param $query
     * @param string $action
     * @return mixed
     */
    public function scopeForAction($query, $action)
    {
        return $query->where('action', $action);
    }
}
