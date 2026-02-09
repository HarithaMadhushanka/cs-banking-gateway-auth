<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class MfaChallenge extends Model
{
    protected $table = 'mfa_challenges';
    public $incrementing = false;
    protected $keyType = 'string';

    protected $fillable = [
        'id',
        'user_id',
        'purpose',
        'otp_hash',
        'expires_at',
        'attempts',
        'status',
        'device_id',
        'correlation_id',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
    ];
}
