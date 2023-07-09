<?php

namespace App\Models\Passport;

use Laravel\Passport\Client as BaseClient;

class Client extends BaseClient
{
    /**
     * クライアントが認可プロンプトを飛ばすべきか判定
     */
    public function skipsAuthorization(): bool
    {
        return true;
    }
}
