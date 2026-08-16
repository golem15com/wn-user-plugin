<?php

namespace Golem15\User\Tests\Unit\Controllers;

use Config;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Golem15\User\Controllers\ApiController;
use Golem15\User\Models\ConsentAudit;
use Golem15\User\Models\User as UserModel;
use Golem15\User\Tests\UserPluginTestCase;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

/**
 * Self-service profile endpoints used by the SPA /settings Profile tab:
 * name/surname update (existing), avatar upload/remove, marketing consent.
 *
 * Invokes controller methods with a built Request so they run under the
 * plain-phpunit harness (plugin routes are not registered there).
 */
class ProfileSelfServiceTest extends UserPluginTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        if (!Config::get('jwt.secret')) {
            Config::set('jwt.secret', 'testing-only-deterministic-jwt-secret-key-0001');
        }
        Config::set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'users']);
        Config::set('auth.providers.users', ['driver' => 'eloquent', 'model' => UserModel::class]);
    }

    protected function makeUser(array $overrides = []): UserModel
    {
        $user = new UserModel();
        $user->fill(array_merge([
            'name' => 'Anna',
            'surname' => 'Nowak',
            'email' => 'anna.nowak@example.tld',
            'password' => 'originalpass1',
            'password_confirmation' => 'originalpass1',
        ], $overrides));
        $user->forceSave();

        return $user->fresh();
    }

    protected function authedRequest(UserModel $user, array $data = [], array $files = []): Request
    {
        $this->app->forgetInstance('tymon.jwt');
        $this->app->forgetInstance('tymon.jwt.parser');

        $request = Request::create('/_user/api/v1/self', 'POST', $data, [], $files);
        $request->headers->set('Authorization', 'Bearer ' . JWTAuth::fromUser($user));

        return $request;
    }

    public function test_update_without_token_returns_401(): void
    {
        $response = (new ApiController())->update(Request::create('/_user/api/v1/update', 'POST', [
            'name' => 'Ada',
            'surname' => 'Kowalska',
            'email' => 'ada@example.tld',
        ]));

        $this->assertSame(401, $response->getStatusCode());
    }

    public function test_update_changes_name_and_surname_and_returns_user_payload(): void
    {
        $user = $this->makeUser();

        $response = (new ApiController())->update($this->authedRequest($user, [
            'name' => 'Ada',
            'surname' => 'Kowalska',
            'email' => $user->email,
        ]));

        $this->assertSame(200, $response->getStatusCode());
        $body = $response->getData(true);
        $this->assertSame('Ada', $body['user']['name']);
        $this->assertSame('Kowalska', $body['user']['surname']);
        $this->assertArrayHasKey('has_avatar', $body['user']);
        $this->assertArrayHasKey('marketing_consent', $body['user']);
        $this->assertFalse($body['user']['has_avatar']);
        $this->assertFalse($body['user']['marketing_consent']);

        $user->refresh();
        $this->assertSame('Ada', $user->name);
        $this->assertSame('Kowalska', $user->surname);
    }

    public function test_marketing_consent_grant_and_withdraw_write_audit(): void
    {
        $user = $this->makeUser(['marketing_consent' => false]);
        $this->assertFalse((bool) $user->marketing_consent);

        $grant = (new ApiController())->updateMarketingConsent(
            $this->authedRequest($user, ['marketing_consent' => true])
        );
        $this->assertSame(200, $grant->getStatusCode());
        $this->assertTrue($grant->getData(true)['user']['marketing_consent']);

        $user->refresh();
        $this->assertTrue((bool) $user->marketing_consent);
        $this->assertNotNull($user->marketing_consent_at);
        $this->assertSame(1, ConsentAudit::where('user_id', $user->id)
            ->where('consent_type', ConsentAudit::CONSENT_TYPE_MARKETING)
            ->where('action', ConsentAudit::ACTION_GRANTED)
            ->count());

        $withdraw = (new ApiController())->updateMarketingConsent(
            $this->authedRequest($user, ['marketing_consent' => false])
        );
        $this->assertSame(200, $withdraw->getStatusCode());
        $this->assertFalse($withdraw->getData(true)['user']['marketing_consent']);

        $user->refresh();
        $this->assertFalse((bool) $user->marketing_consent);
        $this->assertSame(1, ConsentAudit::where('user_id', $user->id)
            ->where('consent_type', ConsentAudit::CONSENT_TYPE_MARKETING)
            ->where('action', ConsentAudit::ACTION_WITHDRAWN)
            ->count());
    }

    public function test_marketing_consent_requires_boolean(): void
    {
        $user = $this->makeUser();

        $response = (new ApiController())->updateMarketingConsent(
            $this->authedRequest($user, [])
        );

        $this->assertSame(422, $response->getStatusCode());
        $this->assertArrayHasKey('marketing_consent', $response->getData(true)['errors']);
    }

    public function test_avatar_rejects_non_image(): void
    {
        $user = $this->makeUser();
        $file = UploadedFile::fake()->create('notes.txt', 20, 'text/plain');

        $response = (new ApiController())->updateAvatar(
            $this->authedRequest($user, [], ['avatar' => $file])
        );

        $this->assertSame(422, $response->getStatusCode());
        $this->assertArrayHasKey('avatar', $response->getData(true)['errors']);
        $user->refresh();
        $this->assertNull($user->avatar);
    }

    public function test_avatar_upload_and_remove(): void
    {
        $user = $this->makeUser();
        $file = UploadedFile::fake()->image('avatar.jpg', 80, 80);

        $upload = (new ApiController())->updateAvatar(
            $this->authedRequest($user, [], ['avatar' => $file])
        );

        $this->assertSame(200, $upload->getStatusCode());
        $body = $upload->getData(true);
        $this->assertTrue($body['user']['has_avatar']);
        $this->assertNotEmpty($body['user']['avatar_url']);

        $user->refresh();
        $this->assertNotNull($user->avatar);

        $remove = (new ApiController())->removeAvatar($this->authedRequest($user));
        $this->assertSame(200, $remove->getStatusCode());
        $this->assertFalse($remove->getData(true)['user']['has_avatar']);

        $user->refresh();
        $user->reloadRelations('avatar');
        $this->assertNull($user->avatar);
    }

    public function test_remove_avatar_without_one_returns_422(): void
    {
        $user = $this->makeUser();

        $response = (new ApiController())->removeAvatar($this->authedRequest($user));

        $this->assertSame(422, $response->getStatusCode());
    }
}
