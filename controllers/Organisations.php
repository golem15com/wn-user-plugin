<?php namespace Golem15\User\Controllers;

use BackendMenu;
use Backend\Classes\Controller;

/**
 * Organisations backend controller (Phase 12, WS-1 / D-11).
 *
 * Provides the WinterCMS RelationController surface on top of the Plan 12-02
 * Organisation data model: an admin can create a second+ organisation and assign
 * existing users to it via the `members` hasMany tab (add|remove). Strictly
 * additive to the core Golem15.User plugin — no existing controller is altered.
 */
class Organisations extends Controller
{
    /**
     * @var array Extensions implemented by this controller.
     */
    public $implement = [
        \Backend\Behaviors\FormController::class,
        \Backend\Behaviors\ListController::class,
        \Backend\Behaviors\RelationController::class,
    ];

    /**
     * @var string `FormController` configuration.
     */
    public $formConfig = 'config_form.yaml';

    /**
     * @var string `ListController` configuration.
     */
    public $listConfig = 'config_list.yaml';

    /**
     * @var string `RelationController` configuration.
     */
    public $relationConfig = 'config_relation.yaml';

    /**
     * @var array Permissions required to view this page.
     */
    public $requiredPermissions = ['golem15.users.access_users'];

    /**
     * Constructor.
     */
    public function __construct()
    {
        parent::__construct();

        BackendMenu::setContext('Golem15.User', 'user', 'organisations');
    }
}
