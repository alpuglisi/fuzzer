<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

// CircleFeed's (category 2's Facebook pick) real photo/tag-detail table
// (CC-LAB-0216/FR-LAB-123, docs/research/category2-social-ugc-
// functionality-and-cwe-research.md sec 3 item 4 / sec 6 row 1). Named
// `0001_01_01_000100` -- after the framework's own default
// `0001_01_01_000000_create_users_table` migration (so `owner_id`'s foreign
// key on `users` is always created after that table exists) and before any
// later-dated app migration.
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('photos', function (Blueprint $table) {
            $table->id();
            $table->foreignId('owner_id')->constrained('users')->cascadeOnDelete();
            $table->string('caption');
            $table->string('image_path');
            $table->boolean('is_private')->default(false);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('photos');
    }
};
