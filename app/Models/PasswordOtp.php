<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class PasswordOtp extends Model
{
    protected $fillable = ['user_id', 'email', 'otp', 'expires_at', 'used'];


    protected $casts = [
        'expires_at' => 'datetime',
        'used' => 'boolean',
    ];


    public function isExpired()
    {
        return $this->expires_at->isPast();
    }
}
