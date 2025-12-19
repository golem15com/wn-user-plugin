<?php namespace Golem15\User\Classes;

use Golem15\User\Models\User;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Winter\Storm\Auth\Manager as StormAuthManager;
use Golem15\User\Models\Settings as UserSettings;
use Golem15\User\Models\UserGroup as UserGroupModel;
use PHPOpenSourceSaver\JWTAuth\Contracts\Providers\Auth;

class AuthManager extends StormAuthManager implements Auth
{
    protected static $instance;

    protected $sessionKey = 'user_auth';

    protected $userModel = 'Golem15\User\Models\User';

    protected $groupModel = 'Golem15\User\Models\UserGroup';

    protected $throttleModel = 'Golem15\User\Models\Throttle';

    public function init()
    {
        $this->useThrottle = UserSettings::get('use_throttle', $this->useThrottle);
        $this->requireActivation = UserSettings::get('require_activation', $this->requireActivation);
        parent::init();
    }

    public function logout(bool $force = false)
    {
        parent::logout();

        // Only invalidate JWT token if one exists
        try {
            if (JWTAuth::getToken()) {
                JWTAuth::invalidate($force);
            }
        } catch (\Exception $e) {
            // Silently catch JWT exceptions during logout
            // The session logout above already succeeded
        }
    }

    /**
     * {@inheritDoc}
     */
    public function extendUserQuery($query)
    {
        $query->withTrashed()->with(['groups', 'avatar']);
    }

    /**
     * {@inheritDoc}
     */
    public function register(array $credentials, $activate = false, $autoLogin = true)
    {
        if ($guest = $this->findGuestUserByCredentials($credentials)) {
            return $this->convertGuestToUser($guest, $credentials, $activate);
        }

        return parent::register($credentials, $activate, $autoLogin);
    }

    //
    // Guest users
    //

    public function findGuestUserByCredentials(array $credentials)
    {
        if ($email = array_get($credentials, 'email')) {
            return $this->findGuestUser($email);
        }

        return null;
    }

    public function findGuestUser($email)
    {
        $query = $this->createUserModelQuery();

        return $user = $query
            ->where('email', $email)
            ->where('is_guest', 1)
            ->first();
    }

    /**
     * Registers a guest user by giving the required credentials.
     *
     * @param array $credentials
     * @return Models\User
     */
    public function registerGuest(array $credentials)
    {
        $user = $this->findGuestUserByCredentials($credentials);
        $newUser = false;

        if (!$user) {
            $user = $this->createUserModel();
            $newUser = true;
        }

        $user->fill($credentials);
        $user->is_guest = true;
        $user->save();

        // Add user to guest group
        if ($newUser && $group = UserGroupModel::getGuestGroup()) {
            $user->groups()->add($group);
        }

        // Prevents revalidation of the password field
        // on subsequent saves to this model object
        $user->password = null;

        return $this->user = $user;
    }

    /**
     * Converts a guest user to a registered user.
     *
     * @param Models\User $user
     * @param array $credentials
     * @param bool $activate
     * @return Models\User
     */
    public function convertGuestToUser($user, $credentials, $activate = false)
    {
        $user->fill($credentials);
        $user->convertToRegistered(false);

        // Remove user from guest group
        if ($group = UserGroupModel::getGuestGroup()) {
            $user->groups()->remove($group);
        }

        if ($activate) {
            $user->attemptActivation($user->getActivationCode());
        }

        // Prevents revalidation of the password field
        // on subsequent saves to this model object
        $user->password = null;

        return $this->user = $user;
    }

    #[\Override] public function byCredentials(array $credentials)
    {
        return $this->attempt($credentials);
    }

    #[\Override] public function byId($id)
    {
        return User::where('id', $id)->count() > 0;
    }

    public function user()
    {
        $user = $this->getUser();
        if (!$user) {
            try {
                $userId = \JWTAuth::getPayload()->get('sub');

                $user = User::where('id', $userId)->with('groups')->firstOrFail();
            } catch (\Exception $e) {
                \Log::error($e->getMessage(). ' '. $e->getTrace());
                return null;
            }
        }

        return $user;
    }
}
