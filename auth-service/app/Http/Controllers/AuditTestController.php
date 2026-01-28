<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class AuditTestController extends Controller
{

    public function test(Request $request)
    {
        return response()->json([
            'ok' => true,
            'audit' => 'logged',
        ]);
    }
}
