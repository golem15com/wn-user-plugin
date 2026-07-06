<?php

namespace Golem15\User\Updates;

use DB;
use Schema;
use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;

class CreateOAuthIdentitiesTable extends Migration
{
    public function up()
    {
        Schema::create('golem15_user_oauth_identities', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('user_id')->unsigned();
            $table->string('provider', 50);
            $table->string('provider_id', 255);
            $table->text('access_token')->nullable();
            $table->text('refresh_token')->nullable();
            $table->timestamp('token_expires_at')->nullable();
            $table->json('profile_data')->nullable();
            $table->timestamp('linked_at')->nullable();
            $table->timestamps();

            // Max one link per provider type per user.
            $table->unique(['user_id', 'provider'], 'oauth_identities_user_provider_unique');
            // Max one WavePath user per provider identity globally — carries forward the
            // old users.oauth_unique_provider_user guarantee.
            $table->unique(['provider', 'provider_id'], 'oauth_identities_provider_identity_unique');

            $table->foreign('user_id')
                ->references('id')
                ->on('users')
                ->onDelete('cascade');
        });

        // Backfill: copy any existing single-slot link on `users` into the new table. This is a
        // raw column copy — encrypt()/decrypt() ciphertext is opaque and table-agnostic, so no
        // decrypt/re-encrypt cycle is needed. The old users.oauth_* columns are left untouched
        // (frozen, read-only from the moment the model layer switches over in the next release)
        // as a forensic safety net; they're dropped in a later migration once production
        // verification confirms zero data loss.
        DB::table('users')
            ->whereNotNull('oauth_provider')
            ->whereNotNull('oauth_provider_id')
            ->orderBy('id')
            ->chunkById(200, function ($rows) {
                foreach ($rows as $row) {
                    DB::table('golem15_user_oauth_identities')->insert([
                        'user_id' => $row->id,
                        'provider' => $row->oauth_provider,
                        'provider_id' => $row->oauth_provider_id,
                        'access_token' => $row->oauth_access_token,
                        'refresh_token' => $row->oauth_refresh_token,
                        'token_expires_at' => $row->oauth_token_expires_at,
                        'profile_data' => $row->oauth_profile_data,
                        'linked_at' => $row->oauth_linked_at,
                        'created_at' => $row->oauth_linked_at ?? now(),
                        'updated_at' => now(),
                    ]);
                }
            });
    }

    public function down()
    {
        Schema::dropIfExists('golem15_user_oauth_identities');
    }
}
