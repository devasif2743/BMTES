<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class OtpMail extends Mailable  implements ShouldQueue
{
    use Queueable, SerializesModels;


    public $otp;
    public $expiresAt;


    public function __construct(string $otp, \DateTimeInterface $expiresAt)
    {
        $this->otp = $otp;
        $this->expiresAt = $expiresAt;
    }


    public function build()
    {
        return $this->subject('Your OTP for password reset')
            ->markdown('emails.otp')
            ->with([
                'otp' => $this->otp,
                'expiresAt' => $this->expiresAt,
            ]);
    }




    /**
     * Get the message content definition.
     */
    public function content(): Content
    {
        return new Content(
            markdown: 'emails.otp',
        );
    }

    /**
     * Get the attachments for the message.
     *
     * @return array<int, \Illuminate\Mail\Mailables\Attachment>
     */
    public function attachments(): array
    {
        return [];
    }
}
