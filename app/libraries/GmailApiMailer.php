<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

class GmailApiMailer
{
    private static $service;

    public static function isConfigured()
    {
        return class_exists(\Google\Client::class)
            && trim((string) config_item('gmail_api_client_id')) !== ''
            && trim((string) config_item('gmail_api_client_secret')) !== ''
            && trim((string) config_item('gmail_api_refresh_token')) !== ''
            && filter_var(config_item('mail_from_address'), FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function sendEmail($recipient, $subject, $text, $html)
    {
        if (!self::isConfigured()) {
            throw new RuntimeException('Gmail API email is not configured. Check GMAIL_API_* and MAIL_FROM_ADDRESS settings, then run Composer install.');
        }
        if (!is_string($recipient) || filter_var($recipient, FILTER_VALIDATE_EMAIL) === false) {
            throw new RuntimeException('The email recipient is invalid.');
        }
        if (!is_string($subject) || trim($subject) === '' || !is_string($text) || !is_string($html)) {
            throw new RuntimeException('The email subject and message bodies are required.');
        }

        $message = new \Google\Service\Gmail\Message();
        $message->setRaw(self::encodeMessage($recipient, $subject, $text, $html));
        self::service()->users_messages->send('me', $message);
    }

    private static function service()
    {
        if (self::$service !== null) {
            return self::$service;
        }

        $client = new \Google\Client();
        $client->setApplicationName((string) config_item('mail_from_name'));
        $client->setClientId((string) config_item('gmail_api_client_id'));
        $client->setClientSecret((string) config_item('gmail_api_client_secret'));
        $client->setScopes([\Google\Service\Gmail::GMAIL_SEND]);

        $token = $client->fetchAccessTokenWithRefreshToken((string) config_item('gmail_api_refresh_token'));
        if (!is_array($token) || isset($token['error']) || empty($token['access_token'])) {
            $description = is_array($token) && isset($token['error_description']) && is_string($token['error_description'])
                ? ': ' . $token['error_description']
                : '';
            throw new RuntimeException('Gmail API OAuth token request failed' . $description);
        }
        $client->setAccessToken($token);
        self::$service = new \Google\Service\Gmail($client);

        return self::$service;
    }

    private static function encodeMessage($recipient, $subject, $text, $html)
    {
        $senderEmail = (string) config_item('mail_from_address');
        $senderName = str_replace(["\r", "\n"], '', (string) config_item('mail_from_name'));
        $safeSubject = str_replace(["\r", "\n"], '', trim($subject));
        $boundary = 'baco360_' . bin2hex(random_bytes(16));
        $headers = [
            'From: =?UTF-8?B?' . base64_encode($senderName) . '?= <' . $senderEmail . '>',
            'To: <' . $recipient . '>',
            'Subject: =?UTF-8?B?' . base64_encode($safeSubject) . '?=',
            'MIME-Version: 1.0',
            'Content-Type: multipart/alternative; boundary="' . $boundary . '"',
        ];
        $message = implode("\r\n", $headers) . "\r\n\r\n"
            . '--' . $boundary . "\r\n"
            . "Content-Type: text/plain; charset=UTF-8\r\n"
            . "Content-Transfer-Encoding: base64\r\n\r\n"
            . chunk_split(base64_encode($text), 76, "\r\n")
            . '--' . $boundary . "\r\n"
            . "Content-Type: text/html; charset=UTF-8\r\n"
            . "Content-Transfer-Encoding: base64\r\n\r\n"
            . chunk_split(base64_encode($html), 76, "\r\n")
            . '--' . $boundary . "--\r\n";

        return rtrim(strtr(base64_encode($message), '+/', '-_'), '=');
    }
}
