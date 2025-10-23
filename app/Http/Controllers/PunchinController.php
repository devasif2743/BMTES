<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\employeeAttendance;
use Illuminate\Support\Facades\Validator;
use Carbon\Carbon;
class PunchinController extends Controller
{
    


    public function store(Request $req)
{
    $userId = auth()->id();
    $today = now()->toDateString();

      $validator=Validator::make($req->all(),[
            'latitude'=>'required|string',
            'longitude'=>'required|string',
             'type' => 'required|in:punch-in,punch-out',

        ]);
    
        if($validator->fails()){
            return response()->json(
                [
                    'status'=>false,
                    'message'=> $validator->errors()->first(),
                ],
               200);
        }
    // Get today's punches
    $todayPunches = \DB::table('attendance')
        ->where('user_id', $userId)
        ->whereDate('date_punchin', $today)
        ->orderBy('id', 'asc')
        ->get();

    // Check Punch In
    if ($req->type == 'punch-in') {
        if ($todayPunches->contains('status', 'punch-in')) {
            return response()->json(['error' => 'You already punched IN today.'], 422);
        }

        // Save punch IN
        \DB::table('attendance')->insert([
            'user_id'   => $userId,
             'latitude'=>$req->latitude,
            'longitude'=>$req->longitude,
            'status'      => 'punch-in',
            'date_punchin'=> now(),
        ]);

        return response()->json(['success' => true, 'message' => 'Punch IN recorded.']);
    }

    // Check Punch Out
    if ($req->type == 'punch-out') {

        // dd($req->type);
        if (!$todayPunches->contains('status', 'punch-in')) {
            return response()->json(['error' => 'You must punch IN before OUT.'], 422);
        }

        if ($todayPunches->contains('status', 'punch-out')) {
            return response()->json(['error' => 'You already punched OUT today.'], 422);
        }

        // Get today's IN time
        $inRecord = $todayPunches->where('status', operator: 'punch-in')->first();
        $inTime = \Carbon\Carbon::parse($inRecord->date_punchin);
        $outTime = now();

        $workedHours = $inTime->diffInMinutes($outTime) / 60; // hours (float)

        // Save punch OUT
        \DB::table('attendance')->insert([
            'user_id'   => $userId,
              'latitude'=>$req->latitude,
            'longitude'=>$req->longitude,
            'status'      => 'punch-out',
            'date_punchin'=> $outTime,
        ]);

        // Save to work_sessions (optional)
        \DB::table('work_sessions')->insert([
            'user_id'       => $userId,
            'in_time'       => $inTime,
            'out_time'      => $outTime,
            'worked_hours'  => round($workedHours, 2), // store 2 decimals
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Punch OUT recorded.',
            'worked_hours' => round($workedHours, 2)
        ]);
    }
}


 public function checkPunchIn1()
    {
        $userId = auth()->user()->id; 
        // OR: $userId = $request->input('user_id'); if you pass user_id in request

        $today = now()->toDateString();

        $punchIn = \DB::table('attendance')
            ->where('user_id', $userId)
            ->where('status', 'punch-in')
            ->whereDate('date_punchin', $today)
            ->first();

        if ($punchIn) {
            return response()->json([
                'punched_in' => true,
                'message' => 'User has already punched IN today.',
                'time' => $punchIn->date_punchin,
            ]);
        }

        return response()->json([
            'punched_in' => false,
            'message' => 'User has not punched IN today.',
        ]);
    }


     public function checkPunchIn()
    {
        $userId = auth()->user()->id; 
        // OR: $userId = $request->input('user_id');

        $today = now()->toDateString();

        // Get today's punches ordered
        $todayPunches = \DB::table('attendance')
            ->where('user_id', $userId)
            ->whereDate('date_punchin', $today)
            ->orderBy('date_punchin', 'asc')
            ->get();

        $punchedIn  = $todayPunches->where('status', 'punch-in')->first();
        $punchedOut = $todayPunches->where('status', 'punch-out')->first();

        $workedHours = null;
        $inTime = $punchedIn ? Carbon::parse($punchedIn->date_punchin)->format('H:i:s') : null;
        $outTime = $punchedOut ? Carbon::parse($punchedOut->date_punchin)->format('H:i:s') : null;

        if ($punchedIn && $punchedOut) {
            $workedHours = round(
                Carbon::parse($punchedIn->date_punchin)->diffInMinutes(Carbon::parse($punchedOut->date_punchin)) / 60,
                2
            );
        }

        return response()->json([
            'punched_in'   => (bool) $punchedIn,
            'punched_out'  => (bool) $punchedOut,
            'in_time'      => $inTime,
            'out_time'     => $outTime,
            'worked_hours' => $workedHours,
            'message' => match (true) {
                !$punchedIn => 'User has not punched IN today.',
                $punchedIn && !$punchedOut => 'User has punched IN but not OUT yet.',
                $punchedIn && $punchedOut => 'User has punched IN and OUT today.',
            }
        ]);
    }

}
