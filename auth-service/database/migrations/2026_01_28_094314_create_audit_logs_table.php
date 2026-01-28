<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('audit_logs', function (Blueprint $table) {
            $table->id();

            // Who (nullable because some events happen before login)
            $table->unsignedBigInteger('user_id')->nullable()->index();

            // What
            $table->string('event_type', 50)->index();

            // Where
            $table->string('ip', 45)->nullable();
            $table->string('user_agent', 255)->nullable();

            // Traceability across services (Kong → Auth → FMS later)
            $table->string('correlation_id', 64)->nullable()->index();

            // Extra structured context
            $table->json('metadata')->nullable();

            // When
            $table->timestamps();
        });
    }


    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('audit_logs');
    }
};
