<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class AuditLog extends Model
{
    protected $table = 'audit_logs';

    protected $fillable = [
        'user_id',
        'event_type',
        'ip',
        'user_agent',
        'correlation_id',
        'metadata',
    ];

    protected $casts = [
        'metadata' => 'array',
    ];
}
