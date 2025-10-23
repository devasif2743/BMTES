@component('mail::message')
# Welcome, {{ $userName }}! 🎉

We’re thrilled to have you on board with **{{ config('app.name') }}**.

@component('mail::button', ['url' => config('app.url')])
Visit Our Website
@endcomponent

Thanks,<br>
The {{ config('app.name') }} Team
@endcomponent