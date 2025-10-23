<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\User;
use App\Models\PasswordOtp;
use Carbon\Carbon;
use App\Mail\OtpMail;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\DB;

use App\Mail\WelcomeMail;    




class AuthController extends Controller
{
    public function register11(Request $req)
    {

        $validator = Validator::make($req->all(), [
            'name' => 'required|string|min:2|max:100',
            'email' => 'required|string|email|max:100|unique:users,email',
            'password' => 'required|min:6',
            'phone' => 'required|digits:10|unique:users,phone',
            'orginazationName' => 'required|string',
            // 'fcm_token'=>'required',
        ]);

        if ($validator->fails()) {
            return response()->json(
                [
                    'status' => false,
                    'message' => $validator->errors()->first(),
                ],
                200
            );
        }

        try {
            $code = substr(str_replace('.', '', microtime(true)), -8);

            $userresult = User::create([
                'name' => $req->name,
                'email' => $req->email,
                'password' => Hash::make($req->password),
                'phone' => $req->phone,
                'orginazationName' => $req->orginazationName,
                'role' => 'Orginazation',
                // 'saas_id'=>env('SAAS_KEY'),
                // 'role'=>'Manager',
            ]);

            $token = JWTAuth::fromUser($userresult); // Generate JWT token for the new user

            $refreshToken = Str::random(60);
            $userresult->refresh_token = hash('sha256', $refreshToken);
            // $userresult->device_fcm_token = $req->fcm_token;
            $userresult->save();

            $role = $userresult->role;

            return response()->json([
                'status' => true,
                'access_token' => $token,
                'refresh_token' => $refreshToken,
                'token_type' => 'bearer',

                'expires_in' => auth()->factory()->getTTL() * 60,

            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => false,
                'message' => $e->getMessage(),

            ]);
        }
    }


    public function registerdddd(Request $req)
    {
        $validator = Validator::make($req->all(), [
            'name' => 'required|string|min:2|max:100',
            'email' => 'required|string|email|max:100|unique:users,email',
            'password' => 'required|min:6',
            'phone' => 'required|digits:10|unique:users,phone',
            'orginazationName' => 'required|string',
            // 'fcm_token'=>'required',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->first(),
            ], 200);
        }

        try {
            $code = substr(str_replace('.', '', microtime(true)), -8);

            $userresult = User::create([
                'name' => $req->name,
                'email' => $req->email,
                'password' => Hash::make($req->password),
                'phone' => $req->phone,
                'orginazationName' => $req->orginazationName,
                'role' => 'Orginazation',
                // 'saas_id'=>env('SAAS_KEY'),
                // 'role'=>'Manager',
            ]);

            $token = JWTAuth::fromUser($userresult); // Generate JWT token for the new user

            $refreshToken = Str::random(60);
            $userresult->refresh_token = hash('sha256', $refreshToken);
            // $userresult->device_fcm_token = $req->fcm_token;
            $userresult->save();

            // --- SEND WELCOME EMAIL (queued if possible) ---

            try {
                Mail::to($req->email)->queue(new WelcomeMail($req->name));
            } catch (\Throwable $e) {

                Log::error('Failed to queue OTP email', [
                    'email' => $req->email,
                    'error' => $e->getMessage(),
                ]);

                return response()->json([
                    'status' => false,
                    'message' => 'Failed to send OTP. Please try again later.',
                ], 200);
            }

            return response()->json([
                'status' => true,
                'access_token' => $token,
                'refresh_token' => $refreshToken,
                'token_type' => 'bearer',
                'expires_in' => auth()->factory()->getTTL() * 60,
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => false,
                'message' => $e->getMessage(),
            ]);
        }
    }

    public function register_111(Request $req)
    {
        $validator = Validator::make($req->all(), [
            'name' => 'required|string|min:2|max:100',
            'email' => 'required|string|email|max:100|unique:users,email',
            'password' => 'required|min:6',
            'phone' => 'required|digits:10|unique:users,phone',
            'orginazationName' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->first(),
            ], 200);
        }

        try {
            $userresult = User::create([
                'name' => $req->name,
                'email' => $req->email,
                'password' => Hash::make($req->password),
                'phone' => $req->phone,
                'orginazationName' => $req->orginazationName,
                'role' => 'Orginazation',
            ]);

            $token = JWTAuth::fromUser($userresult);
            $refreshToken = Str::random(60);
            $userresult->refresh_token = hash('sha256', $refreshToken);
            $userresult->save();

            // ---- MAIL DISPATCH + LOGGING ----


          


             try {
            // Mail::to('sk.asif0490@gmil.com')->queue(new WelcomeMail('Asif'));

             Mail::to('sk.asif0490@gmil.com')->queue(new WelcomeMail('Debug User'));
              return 'WelcomeMail send() returned OK';
        } catch (\Throwable $e) {

            Log::error('Failed to queue OTP email', [
                // 'email' => $email,
                'error' => $e->getMessage(),
            ]);

            return response()->json([
                'status' => false,
                'message' => 'Failed to send OTP. Please try again later.',
                 'error' => $e->getMessage(),
            ], 200);
        }

            return response()->json([
                'status' => true,
                'access_token' => $token,
                'refresh_token' => $refreshToken,
                'token_type' => 'bearer',
                'expires_in' => auth()->factory()->getTTL() * 60,
                // 'mail_status' => $mailStatus, // queued | sent | failed | not_attempted
            ]);
        } catch (\Exception $e) {
            Log::error('Registration failed', ['error' => $e->getMessage(), 'trace' => $e->getTraceAsString()]);
            return response()->json([
                'status' => false,
                'message' => $e->getMessage(),
            ], 500);
        }
    }


    public function register(Request $req)
    {
        $validator = Validator::make($req->all(), [
            'name' => 'required|string|min:2|max:100',
            'email' => 'required|string|email|max:100|unique:users,email',
            'password' => 'required|min:6',
            'phone' => 'required|digits:10|unique:users,phone',
            'orginazationName' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->first(),
            ], 200);
        }

        try {
            $userresult = User::create([
                'name' => $req->name,
                'email' => $req->email,
                'password' => Hash::make($req->password),
                'phone' => $req->phone,
                'orginazationName' => $req->orginazationName,
                'role' => 'Orginazation',
            ]);

            $token = JWTAuth::fromUser($userresult);
            $refreshToken = Str::random(60);
            $userresult->refresh_token = hash('sha256', $refreshToken);
            $userresult->save();

            // send welcome mail (use real user email)
            try {
                // use the real email from request
                Mail::to($userresult->email)->queue(new WelcomeMail($userresult->name));

                // Optionally set a flag on user that mail queued:
                // $userresult->mail_status = 'queued';
                // $userresult->save();

            } catch (\Throwable $e) {
                Log::error('Failed to queue WelcomeMail', [
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString(),
                ]);

                // don't fail the whole registration for mail issue — return warning
                return response()->json([
                    'status' => false,
                    'message' => 'Failed to send welcome email. Please try again later.',
                    'error' => $e->getMessage(),
                ], 200);
            }

            return response()->json([
                'status' => true,
                'access_token' => $token,
                'refresh_token' => $refreshToken,
                'token_type' => 'bearer',
                'expires_in' => auth()->factory()->getTTL() * 60,
            ]);
        } catch (\Exception $e) {
            Log::error('Registration failed', ['error' => $e->getMessage(), 'trace' => $e->getTraceAsString()]);
            return response()->json([
                'status' => false,
                'message' => $e->getMessage(),
            ], 500);
        }
    }


    public function login(Request $req)
    {

        $validator = Validator::make($req->all(), [
            'username' => 'required|string',
            'password' => 'required'
        ]);

        if ($validator->fails()) {
            return response()->json(
                [
                    'status' => false,
                    'message' => $validator->errors()->first(),
                ],
                200
            );
        }
        $loginField = filter_var($req->username, FILTER_VALIDATE_EMAIL) ? 'email' : 'phone';

        $credentials = [
            $loginField => $req->username,
            'password' => $req->password
        ];

        try {

            if (!$token = auth()->attempt($credentials)) {
                return response()->json([
                    'status' => false,
                    'message' => 'Invalid Username or Password',
                ], 200);
            }

            $user = auth()->user();
            $role = auth()->user()->role;

            if ($role == "Orginazation") {
                $refreshToken = Str::random(60); // Laravel helper for secure random string

                $user->refresh_token = hash('sha256', $refreshToken);
                $user->save();

                return response()->json([
                    'status' => true,
                    'access_token' => $token,
                    'refresh_token' => $refreshToken,
                    'token_type' => 'bearer',
                    'role' => $role,
                    'expires_in' => auth()->factory()->getTTL() * 60
                ]);
            } else {
                return response()->json([
                    'status' => false,
                    'message' => 'Your not Orginazation Role'
                ]);
            }

            // return $this->resondedJwtToken($token);
        } catch (\Exception $e) {
            return response()->json([
                'status' => false,
                'message' => $e->getMessage()
            ], 200);
        }
    }

    public function sendOtp(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|exists:users,email',
        ]);

        if ($validator->fails()) {

            return response()->json([
                'status' => false,
                'message' => $validator->errors()->first(),
            ], 200);
        }

        $email = $request->input('email');


        $limiterKey = 'forgot-otp:' . sha1($email);
        if (RateLimiter::tooManyAttempts($limiterKey, 5)) {
            return response()->json([
                'status' => false,
                'message' => 'Too many OTP requests. Try again later.',
            ], 200);
        }
        RateLimiter::hit($limiterKey, 3600);


        $user = User::where('email', $email)->first();

        // create OTP
        $otpPlain = (string) random_int(100000, 999999); // 6-digit numeric
        $expiresAt = Carbon::now()->addMinutes(15);

        // store hashed OTP in DB
        $otpRecord = PasswordOtp::create([
            'user_id' => $user->id,
            'email' => $email,
            'otp' => Hash::make($otpPlain),
            'expires_at' => $expiresAt,
            'used' => false,
        ]);


        try {
            Mail::to($email)->queue(new OtpMail($otpPlain, $expiresAt));
        } catch (\Throwable $e) {

            Log::error('Failed to queue OTP email', [
                'email' => $email,
                'error' => $e->getMessage(),
            ]);

            return response()->json([
                'status' => false,
                'message' => 'Failed to send OTP. Please try again later.',
            ], 200);
        }

        return response()->json([
            'status' => true,
            'message' => 'If an account exists for this email, an OTP has been sent.',
        ], 200);
    }

    public function verifyOtp(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|exists:users,email',
            'otp' => 'required|string',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->first()
            ], 200);
        }

        $email = $request->input('email');
        $otpProvided = $request->input('otp');
        $newPassword = $request->input('password');


        $limiterKey = 'verify-otp:' . sha1($email);
        if (RateLimiter::tooManyAttempts($limiterKey, 5)) {
            return response()->json([
                'status' => false,
                'message' => 'Too many verification attempts. Try again later.'
            ], 200);
        }

        try {

            $otpRecord = PasswordOtp::where('email', $email)
                ->where('used', false)
                ->orderBy('created_at', 'desc')
                ->first();

            if (! $otpRecord) {

                RateLimiter::hit($limiterKey, 3600);
                return response()->json(['status' => false, 'message' => 'OTP not found or already used.'], 200);
            }


            if (Carbon::now()->greaterThan($otpRecord->expires_at)) {
                // mark it used/expired optionally
                $otpRecord->used = true;
                $otpRecord->save();
                RateLimiter::hit($limiterKey, 3600);
                return response()->json(['status' => false, 'message' => 'OTP expired.'], 200);
            }

            // 5) Validate OTP value (hashed in DB)
            if (! Hash::check($otpProvided, $otpRecord->otp)) {
                RateLimiter::hit($limiterKey, 3600);
                return response()->json(['status' => false, 'message' => 'Invalid OTP.'], 200);
            }

            // 6) Atomically mark OTP as used to prevent reuse (race-proof)
            $updated = DB::table('password_otps')
                ->where('id', $otpRecord->id)
                ->where('used', false)
                ->update(['used' => true, 'updated_at' => now()]);

            if (! $updated) {
                // Another request consumed it concurrently
                RateLimiter::hit($limiterKey, 3600);
                return response()->json(['status' => false, 'message' => 'OTP already used.'], 409);
            }

            // 7) Update user password inside DB transaction (atomic with OTP marking already done)
            DB::beginTransaction();
            $user = User::where('email', $email)->first();

            if (! $user) {
                DB::rollBack();
                Log::warning('verifyOtp: user not found after OTP check', ['email' => $email, 'otp_id' => $otpRecord->id]);
                return response()->json(['status' => false, 'message' => 'User not found.'], 404);
            }

            $user->password = Hash::make($newPassword);
            $user->save();

            DB::commit();

            // 8) On success, clear the limiter for this email
            RateLimiter::clear($limiterKey);

            return response()->json(['status' => true, 'message' => 'Password updated successfully.'], 200);
        } catch (\Throwable $e) {
            DB::rollBack();
            Log::error('verifyOtp: exception', [
                'email' => $email,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json(['status' => false, 'message' => 'An error occurred. Please try again later.'], 500);
        }
    }
}
