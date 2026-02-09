<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('mfa_challenges', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->unsignedBigInteger('user_id')->index();

            $table->string('purpose', 32)->default('login_step_up');
            $table->string('otp_hash', 255);

            $table->timestamp('expires_at')->index();
            $table->unsignedInteger('attempts')->default(0);
            $table->string('status', 16)->default('pending'); // pending, verified, expired, locked

            $table->string('device_id', 128)->nullable()->index();
            $table->string('correlation_id', 64)->nullable()->index();

            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('mfa_challenges');
    }
};
