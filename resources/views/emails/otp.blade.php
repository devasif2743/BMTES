@component('mail::message')
# Password Reset OTP


Your OTP for password reset is **{{ $otp }}**.


It will expire at **{{ $expiresAt->format('Y-m-d H:i:s') }}** (server time).


If you didn't request this, ignore this email.


Thanks,
{{ config('app.name') }}
@endcomponent