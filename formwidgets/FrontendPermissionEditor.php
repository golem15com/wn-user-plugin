<?php namespace Golem15\User\FormWidgets;

use Backend\Classes\FormWidgetBase;
use Golem15\User\Models\FrontendPermission;

class FrontendPermissionEditor extends FormWidgetBase
{
    /**
     * @var string Mode: 'checkbox' for groups, 'radio' for users
     */
    public $mode = 'radio';

    public function init()
    {
        $this->fillFromConfig(['mode']);
    }

    public function render()
    {
        $this->prepareVars();
        return $this->makePartial('frontendpermissioneditor');
    }

    public function prepareVars()
    {
        if ($this->formField->disabled) {
            $this->previewMode = true;
        }

        $permissionsData = $this->formField->getValueFromData($this->model);
        if (!is_array($permissionsData)) {
            $permissionsData = [];
        }

        $this->vars['mode'] = $this->mode;
        $this->vars['permissions'] = FrontendPermission::listTabbedPermissions();
        $this->vars['baseFieldName'] = $this->getFieldName();
        $this->vars['permissionsData'] = $permissionsData;
        $this->vars['field'] = $this->formField;
    }

    public function getSaveValue($value)
    {
        return is_array($value) ? array_map('intval', $value) : [];
    }

    protected function loadAssets()
    {
        $this->addCss('/modules/backend/formwidgets/permissioneditor/assets/css/permissioneditor.css', 'core');
        $this->addJs('/modules/backend/formwidgets/permissioneditor/assets/js/permissioneditor.js', 'core');
    }
}
