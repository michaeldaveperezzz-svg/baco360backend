<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');
require_once __DIR__ . '/ApiBaseController.php';
require_once APP_DIR . 'libraries/SmtpMailer.php';

class AuthController extends ApiBaseController
{
    private const ONE_TIME_CODE_TTL_SECONDS = 900;
    private const ONE_TIME_CODE_RESEND_DELAY_SECONDS = 60;

    public function login()
    {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $email = strtolower(trim($input['email'] ?? ''));
        $password = $input['password'] ?? '';

        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || !is_string($password) || $password === '') {
            $this->api->respond_error('A valid email and password are required.', 400);
        }

        $user = $this->db->raw(
            'SELECT id, name, email, phone, password, password_is_set, role, is_active, auth_version, email_verified_at, profile_photo, created_at
             FROM users WHERE email = ? LIMIT 1',
            [$email]
        )->fetch(PDO::FETCH_ASSOC);

        if (!$user || !password_verify($password, $user['password'])) {
            $this->api->respond_error('Invalid email or password.', 401);
        }
        if ($user['role'] === 'resident' && empty($user['email_verified_at'])) {
            $this->api->respond_error('Please verify your email address before signing in.', 403);
        }
        if ((int) $user['is_active'] !== 1) {
            if ($user['role'] !== 'resident') {
                $this->api->respond_error('Account is inactive.', 403);
            }
            if (!filter_var($input['reactivate'] ?? false, FILTER_VALIDATE_BOOLEAN)) {
                $this->api->respond_error('This account is deactivated. Confirm reactivation to continue.', 403);
            }
            if (!$this->db->transaction()) {
                $this->api->respond_error('Could not reactivate the account. Please try again.', 500);
            }
            try {
                $this->db->raw('UPDATE users SET is_active = 1, updated_at = NOW() WHERE id = ?', [$user['id']]);
                $this->actor = $user;
                $this->audit('reactivated', 'users', $user['id'], 'Resident reactivated their account.');
                $this->db->commit();
            } catch (Throwable $error) {
                $this->db->roll_back();
                throw $error;
            }
            $user['is_active'] = 1;
        }
        if ((int) $user['password_is_set'] !== 1) {
            $this->db->raw(
                'UPDATE users SET password_is_set = 1 WHERE id = ?',
                [$user['id']]
            );
        }
        $tokens = $this->api->issue_tokens([
            'id' => $user['id'],
            'role' => $user['role'],
            'auth_version' => (int) $user['auth_version'],
        ]);
        $this->actor = $user;
        $this->audit('login', 'auth', $user['id'], 'Signed in with email and password.');
        unset($user['password'], $user['password_is_set']);
        $user = $this->userWithSettings($user);
        $this->respondSuccess(['user' => $user, 'tokens' => $tokens], 'Login successful');
    }

    public function register()
    {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $name = trim($input['name'] ?? '');
        $email = strtolower(trim($input['email'] ?? ''));
        $phone = trim($input['phone'] ?? '');
        $password = $input['password'] ?? '';

        if ($name === '' || strlen($name) > 150 || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 150) {
            $this->api->respond_error('Enter a valid name and email address.', 422);
        }
        if (!is_string($password) || strlen($password) < 8 || $password !== ($input['password_confirmation'] ?? null)) {
            $this->api->respond_error('Passwords must match and contain at least 8 characters.', 422);
        }
        if (!SmtpMailer::isConfigured()) {
            $this->api->respond_error('Email verification is not configured. Please try again later.', 503);
        }
        $existingUser = $this->db->raw(
            'SELECT id, role, email_verified_at FROM users WHERE email = ? LIMIT 1',
            [$email]
        )->fetch(PDO::FETCH_ASSOC);
        if ($existingUser) {
            if ($existingUser['role'] === 'resident' && empty($existingUser['email_verified_at'])) {
                $this->api->respond([
                    'error' => 'This account is already waiting for email verification.',
                    'status' => 409,
                    'code' => 'EMAIL_VERIFICATION_PENDING',
                ], 409);
            }
            $this->api->respond_error('An account with this email already exists.', 409);
        }

        $verificationCode = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        if (!$this->db->transaction()) {
            $this->api->respond_error('Could not start account registration. Please try again.', 500);
        }
        try {
            $this->db->raw(
                'INSERT INTO users (name, email, phone, password, password_is_set, role, is_active, email_verified_at, created_at, updated_at)
                 VALUES (?, ?, ?, ?, 1, ?, 1, NULL, NOW(), NOW())',
                [$name, $email, $phone ?: null, password_hash($password, PASSWORD_DEFAULT), 'resident']
            );
            $user = $this->getUserByEmail($email);
            if (!$user) {
                throw new RuntimeException('The newly registered user could not be loaded.');
            }
            $this->db->raw(
                'INSERT INTO notification_settings (user_id, sms_enabled, email_enabled, report_updates_enabled, resolution_updates_enabled)
                 VALUES (?, ?, ?, 1, 1)',
                [
                    $user['id'],
                    !array_key_exists('sms_enabled', $input) || !empty($input['sms_enabled']) ? 1 : 0,
                    !array_key_exists('email_enabled', $input) || !empty($input['email_enabled']) ? 1 : 0,
                ]
            );
            $this->db->raw(
                'INSERT INTO email_verification_tokens (user_id, code_hash, expires_at, sent_at, attempts)
                 VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 15 MINUTE), NOW(), 0)',
                [$user['id'], $this->hashOneTimeCode($verificationCode)]
            );
            $this->db->commit();
        } catch (Throwable $error) {
            $this->db->roll_back();
            if ($error instanceof PDOException && $error->getCode() === '23000') {
                $existingUser = $this->db->raw(
                    'SELECT role, email_verified_at FROM users WHERE email = ? LIMIT 1',
                    [$email]
                )->fetch(PDO::FETCH_ASSOC);
                if ($existingUser && $existingUser['role'] === 'resident' && empty($existingUser['email_verified_at'])) {
                    $this->api->respond([
                        'error' => 'This account is already waiting for email verification.',
                        'status' => 409,
                        'code' => 'EMAIL_VERIFICATION_PENDING',
                    ], 409);
                }
                $this->api->respond_error('An account with this email already exists.', 409);
            }
            error_log('Could not complete account registration: ' . $error->getMessage());
            $this->api->respond_error('Could not complete account registration. Please try again.', 500);
        }

        $emailSent = false;
        try {
            SmtpMailer::sendEmailVerificationCode($email, $name, $verificationCode);
            $emailSent = true;
        } catch (Throwable $error) {
            error_log('Could not send account verification email for user ' . $user['id'] . ': ' . $error->getMessage());
            try {
                $this->db->raw('DELETE FROM email_verification_tokens WHERE user_id = ?', [$user['id']]);
            } catch (Throwable $cleanupError) {
                error_log('Could not remove unsent verification code for user ' . $user['id'] . ': ' . $cleanupError->getMessage());
            }
        }

        $this->respondSuccess(
            [
                'email' => $email,
                'verification_email_sent' => $emailSent,
                'expires_in_seconds' => $emailSent ? self::ONE_TIME_CODE_TTL_SECONDS : 0,
                'resend_after_seconds' => $emailSent ? self::ONE_TIME_CODE_RESEND_DELAY_SECONDS : 0,
            ],
            $emailSent
                ? 'Account created. Enter the verification code sent to your email.'
                : 'Account created, but the verification email could not be sent. Request a new code to continue.',
            201
        );
    }

    public function resendEmailVerification()
    {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $email = is_string($input['email'] ?? null) ? strtolower(trim($input['email'])) : '';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 150) {
            $this->api->respond_error('Enter a valid email address.', 422);
        }
        if (!SmtpMailer::isConfigured()) {
            $this->api->respond_error('Email verification is not configured. Please try again later.', 503);
        }

        $user = $this->db->raw(
            'SELECT id, name, email, email_verified_at
             FROM users WHERE email = ? AND role = ? LIMIT 1',
            [$email, 'resident']
        )->fetch(PDO::FETCH_ASSOC);
        if (!$user || !empty($user['email_verified_at'])) {
            $this->respondSuccess(
                ['requested' => true] + $this->codeTiming(),
                'If this address belongs to an unverified resident account, a code will be sent.'
            );
        }

        $existingRequest = $this->db->raw(
            'SELECT
                GREATEST(0, TIMESTAMPDIFF(SECOND, NOW(), expires_at)) AS expires_in_seconds,
                GREATEST(0, ' . self::ONE_TIME_CODE_RESEND_DELAY_SECONDS . ' - TIMESTAMPDIFF(SECOND, sent_at, NOW())) AS resend_after_seconds
             FROM email_verification_tokens WHERE user_id = ? LIMIT 1',
            [$user['id']]
        )->fetch(PDO::FETCH_ASSOC);
        if ($existingRequest && (int) $existingRequest['resend_after_seconds'] > 0) {
            $this->respondSuccess(
                ['requested' => true] + $this->codeTiming($existingRequest),
                'If this address belongs to an unverified resident account, a code will be sent.'
            );
        }

        $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        if (!$this->db->transaction()) {
            $this->api->respond_error('Could not request a verification code. Please try again.', 500);
        }
        try {
            $this->db->raw(
                'INSERT INTO email_verification_tokens (user_id, code_hash, expires_at, sent_at, attempts)
                 VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 15 MINUTE), NOW(), 0)
                 ON DUPLICATE KEY UPDATE code_hash = VALUES(code_hash), expires_at = VALUES(expires_at),
                    sent_at = VALUES(sent_at), attempts = 0',
                [$user['id'], $this->hashOneTimeCode($code)]
            );
            $this->db->commit();
        } catch (Throwable $error) {
            $this->db->roll_back();
            error_log('Could not create email verification code for user ' . $user['id'] . ': ' . $error->getMessage());
            $this->api->respond_error('Could not request a verification code. Please try again.', 500);
        }

        $emailSent = false;
        try {
            SmtpMailer::sendEmailVerificationCode($email, (string) $user['name'], $code);
            $emailSent = true;
        } catch (Throwable $error) {
            error_log('Could not resend account verification email for user ' . $user['id'] . ': ' . $error->getMessage());
            try {
                $this->db->raw('DELETE FROM email_verification_tokens WHERE user_id = ?', [$user['id']]);
            } catch (Throwable $cleanupError) {
                error_log('Could not remove unsent verification code for user ' . $user['id'] . ': ' . $cleanupError->getMessage());
            }
        }

        $this->respondSuccess(
            ['requested' => true] + $this->codeTiming($emailSent ? null : [
                'expires_in_seconds' => 0,
                'resend_after_seconds' => 0,
            ]),
            'If this address belongs to an unverified resident account, a code will be sent.'
        );
    }

    public function verifyEmail()
    {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $email = is_string($input['email'] ?? null) ? strtolower(trim($input['email'])) : '';
        $code = $input['code'] ?? '';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 150
            || !is_string($code) || preg_match('/\A[0-9]{6}\z/', $code) !== 1) {
            $this->api->respond_error('Enter a valid email address and 6-digit verification code.', 422);
        }
        if (!$this->db->transaction()) {
            $this->api->respond_error('Could not verify the email. Please try again.', 500);
        }

        $verifiedUser = null;
        try {
            $user = $this->db->raw(
                'SELECT id, name, email, phone, role, is_active, auth_version, email_verified_at, profile_photo, created_at
                 FROM users WHERE email = ? AND role = ? LIMIT 1 FOR UPDATE',
                [$email, 'resident']
            )->fetch(PDO::FETCH_ASSOC);
            if ($user && empty($user['email_verified_at'])) {
                $token = $this->db->raw(
                    'SELECT code_hash, attempts, (expires_at > NOW()) AS is_valid
                     FROM email_verification_tokens WHERE user_id = ? LIMIT 1 FOR UPDATE',
                    [$user['id']]
                )->fetch(PDO::FETCH_ASSOC);
                if ($token && (int) $token['is_valid'] === 1 && (int) $token['attempts'] < 5
                    && hash_equals((string) $token['code_hash'], $this->hashOneTimeCode($code))) {
                    $this->db->raw(
                        'UPDATE users SET email_verified_at = NOW(), updated_at = NOW() WHERE id = ?',
                        [$user['id']]
                    );
                    $this->db->raw('DELETE FROM email_verification_tokens WHERE user_id = ?', [$user['id']]);
                    $verifiedUser = $this->db->raw(
                        'SELECT id, name, email, phone, role, is_active, auth_version, email_verified_at, profile_photo, created_at
                         FROM users WHERE id = ? LIMIT 1',
                        [$user['id']]
                    )->fetch(PDO::FETCH_ASSOC);
                } elseif ($token) {
                    $attempts = (int) $token['attempts'] + 1;
                    if ($attempts >= 5 || (int) $token['is_valid'] !== 1) {
                        $this->db->raw('DELETE FROM email_verification_tokens WHERE user_id = ?', [$user['id']]);
                    } else {
                        $this->db->raw(
                            'UPDATE email_verification_tokens SET attempts = ? WHERE user_id = ?',
                            [$attempts, $user['id']]
                        );
                    }
                }
            }
            $this->db->commit();
        } catch (Throwable $error) {
            $this->db->roll_back();
            throw $error;
        }

        if (!$verifiedUser) {
            $this->api->respond_error('The verification code is invalid or expired. Request a new code and try again.', 422);
        }

        $welcomeEmailSent = true;
        try {
            SmtpMailer::sendWelcomeEmail($email, (string) $verifiedUser['name']);
        } catch (Throwable $error) {
            $welcomeEmailSent = false;
            error_log('Could not send welcome email for verified user ' . $verifiedUser['id'] . ': ' . $error->getMessage());
        }

        $tokens = $this->api->issue_tokens([
            'id' => $verifiedUser['id'],
            'role' => $verifiedUser['role'],
            'auth_version' => (int) $verifiedUser['auth_version'],
        ]);
        $this->actor = $verifiedUser;
        $this->audit('login', 'auth', $verifiedUser['id'], 'Signed in after verifying email.');
        $authenticatedUser = $this->userWithSettings($verifiedUser);

        $this->respondSuccess(
            [
                'email_verified' => true,
                'welcome_email_sent' => $welcomeEmailSent,
                'user' => $authenticatedUser,
                'tokens' => $tokens,
            ],
            $welcomeEmailSent
                ? 'Email verified successfully. You are now signed in.'
                : 'Email verified successfully, but the welcome email could not be sent. You are now signed in.'
        );
    }

    public function requestPasswordReset()
    {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $email = is_string($input['email'] ?? null) ? strtolower(trim($input['email'])) : '';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 150) {
            $this->api->respond_error('Enter a valid email address.', 422);
        }
        if (!SmtpMailer::isConfigured()) {
            $this->api->respond_error('Password reset email is not configured. Please try again later.', 503);
        }

        $genericMessage = 'If an account exists for that email, a password reset code will be sent.';
        $user = $this->db->raw(
            'SELECT id, name, email FROM users WHERE email = ? AND role = ? LIMIT 1',
            [$email, 'resident']
        )->fetch(PDO::FETCH_ASSOC);
        if (!$user) {
            $this->respondSuccess(['requested' => true] + $this->codeTiming(), $genericMessage);
        }

        $existingRequest = $this->db->raw(
            'SELECT
                GREATEST(0, TIMESTAMPDIFF(SECOND, NOW(), expires_at)) AS expires_in_seconds,
                GREATEST(0, ' . self::ONE_TIME_CODE_RESEND_DELAY_SECONDS . ' - TIMESTAMPDIFF(SECOND, sent_at, NOW())) AS resend_after_seconds
             FROM password_reset_tokens WHERE user_id = ? LIMIT 1',
            [$user['id']]
        )->fetch(PDO::FETCH_ASSOC);
        if ($existingRequest && (int) $existingRequest['resend_after_seconds'] > 0) {
            $this->respondSuccess(['requested' => true] + $this->codeTiming($existingRequest), $genericMessage);
        }

        $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        if (!$this->db->transaction()) {
            $this->api->respond_error('Could not request a password reset. Please try again.', 500);
        }
        try {
            $this->db->raw(
                'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, sent_at, attempts)
                 VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 15 MINUTE), NOW(), 0)
                 ON DUPLICATE KEY UPDATE token_hash = VALUES(token_hash), expires_at = VALUES(expires_at),
                    sent_at = VALUES(sent_at), attempts = 0',
                [$user['id'], $this->hashOneTimeCode($code)]
            );
            $this->db->commit();
        } catch (Throwable $error) {
            $this->db->roll_back();
            error_log('Could not create password reset code for user ' . $user['id'] . ': ' . $error->getMessage());
            $this->api->respond_error('Could not request a password reset. Please try again.', 500);
        }

        $emailSent = false;
        try {
            SmtpMailer::sendPasswordResetCode($email, (string) $user['name'], $code);
            $emailSent = true;
        } catch (Throwable $error) {
            error_log('Could not send password reset email for user ' . $user['id'] . ': ' . $error->getMessage());
            try {
                $this->db->raw('DELETE FROM password_reset_tokens WHERE user_id = ?', [$user['id']]);
            } catch (Throwable $cleanupError) {
                error_log('Could not remove unsent password reset code for user ' . $user['id'] . ': ' . $cleanupError->getMessage());
            }
        }

        $this->respondSuccess(
            ['requested' => true] + $this->codeTiming($emailSent ? null : [
                'expires_in_seconds' => 0,
                'resend_after_seconds' => 0,
            ]),
            $genericMessage
        );
    }

    public function verifyPasswordResetCode()
    {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $email = is_string($input['email'] ?? null) ? strtolower(trim($input['email'])) : '';
        $code = $input['code'] ?? '';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 150
            || !is_string($code) || preg_match('/\A[0-9]{6}\z/', $code) !== 1) {
            $this->api->respond_error('Enter a valid email address and 6-digit reset code.', 422);
        }
        if (!$this->db->transaction()) {
            $this->api->respond_error('Could not verify the reset code. Please try again.', 500);
        }

        $codeValid = false;
        try {
            $user = $this->db->raw(
                'SELECT id FROM users WHERE email = ? AND role = ? LIMIT 1 FOR UPDATE',
                [$email, 'resident']
            )->fetch(PDO::FETCH_ASSOC);
            if ($user) {
                $token = $this->db->raw(
                    'SELECT token_hash, attempts, (expires_at > NOW()) AS is_valid
                     FROM password_reset_tokens WHERE user_id = ? LIMIT 1 FOR UPDATE',
                    [$user['id']]
                )->fetch(PDO::FETCH_ASSOC);
                if ($token && (int) $token['is_valid'] === 1 && (int) $token['attempts'] < 5
                    && hash_equals((string) $token['token_hash'], $this->hashOneTimeCode($code))) {
                    $codeValid = true;
                } elseif ($token) {
                    $attempts = (int) $token['attempts'] + 1;
                    if ($attempts >= 5 || (int) $token['is_valid'] !== 1) {
                        $this->db->raw('DELETE FROM password_reset_tokens WHERE user_id = ?', [$user['id']]);
                    } else {
                        $this->db->raw(
                            'UPDATE password_reset_tokens SET attempts = ? WHERE user_id = ?',
                            [$attempts, $user['id']]
                        );
                    }
                }
            }
            $this->db->commit();
        } catch (Throwable $error) {
            $this->db->roll_back();
            throw $error;
        }

        if (!$codeValid) {
            $this->api->respond_error('The reset code is invalid or expired. Request a new code and try again.', 422);
        }

        $this->respondSuccess(['code_valid' => true], 'Reset code verified. Choose a new password.');
    }

    public function resetPassword()
    {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $email = is_string($input['email'] ?? null) ? strtolower(trim($input['email'])) : '';
        $code = $input['code'] ?? '';
        $password = $input['password'] ?? null;
        $confirmation = $input['password_confirmation'] ?? null;
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 150
            || !is_string($code) || preg_match('/\A[0-9]{6}\z/', $code) !== 1) {
            $this->api->respond_error('Enter a valid email address and 6-digit reset code.', 422);
        }
        if (!is_string($password) || strlen($password) < 8 || $password !== $confirmation) {
            $this->api->respond_error('Passwords must match and contain at least 8 characters.', 422);
        }
        if (!$this->db->transaction()) {
            $this->api->respond_error('Could not reset the password. Please try again.', 500);
        }

        $passwordReset = false;
        try {
            $user = $this->db->raw(
                'SELECT id FROM users WHERE email = ? AND role = ? LIMIT 1 FOR UPDATE',
                [$email, 'resident']
            )->fetch(PDO::FETCH_ASSOC);
            if ($user) {
                $token = $this->db->raw(
                    'SELECT token_hash, attempts, (expires_at > NOW()) AS is_valid
                     FROM password_reset_tokens WHERE user_id = ? LIMIT 1 FOR UPDATE',
                    [$user['id']]
                )->fetch(PDO::FETCH_ASSOC);
                if ($token && (int) $token['is_valid'] === 1 && (int) $token['attempts'] < 5
                    && hash_equals((string) $token['token_hash'], $this->hashOneTimeCode($code))) {
                    $this->db->raw(
                        'UPDATE users SET password = ?, password_is_set = 1,
                            auth_version = auth_version + 1, updated_at = NOW() WHERE id = ?',
                        [password_hash($password, PASSWORD_DEFAULT), $user['id']]
                    );
                    $this->db->raw('DELETE FROM password_reset_tokens WHERE user_id = ?', [$user['id']]);
                    $this->db->raw('DELETE FROM refresh_tokens WHERE user_id = ?', [$user['id']]);
                    $this->audit('password_reset', 'users', $user['id'], 'Password reset with an email verification code.', $user['id']);
                    $passwordReset = true;
                } elseif ($token) {
                    $attempts = (int) $token['attempts'] + 1;
                    if ($attempts >= 5 || (int) $token['is_valid'] !== 1) {
                        $this->db->raw('DELETE FROM password_reset_tokens WHERE user_id = ?', [$user['id']]);
                    } else {
                        $this->db->raw(
                            'UPDATE password_reset_tokens SET attempts = ? WHERE user_id = ?',
                            [$attempts, $user['id']]
                        );
                    }
                }
            }
            $this->db->commit();
        } catch (Throwable $error) {
            $this->db->roll_back();
            throw $error;
        }

        if (!$passwordReset) {
            $this->api->respond_error('The reset code is invalid or expired. Request a new code and try again.', 422);
        }

        $this->respondSuccess(['password_reset' => true], 'Password reset successfully. You can now sign in.');
    }

    public function googleSignIn()
    {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $idToken = $input['id_token'] ?? '';
        $intent = $input['intent'] ?? '';
        $clientId = trim((string) getenv('GOOGLE_CLIENT_ID'));

        if (!is_string($idToken) || $idToken === '' || strlen($idToken) > 8192
            || !in_array($intent, ['sign_in', 'sign_up', 'reactivate'], true)) {
            $this->api->respond_error('A Google credential and valid sign-in intent are required.', 422);
        }
        if ($clientId === '') {
            $this->api->respond_error('Google sign-in is not configured.', 503);
        }

        $identity = $this->verifyGoogleIdToken($idToken, $clientId);
        if (!$identity) {
            $this->api->respond_error('The Google credential is invalid or expired. Please try again.', 401);
        }

        $email = strtolower(trim($identity['email']));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 150) {
            $this->api->respond_error('The Google account has an unsupported email address.', 422);
        }

        $user = $this->getUserByEmail($email);
        $accountCreated = false;
        if (!$user && in_array($intent, ['sign_in', 'reactivate'], true)) {
            $this->api->respond_error('No Baco360 account is linked to this Google email. Create an account first.', 404);
        }

        if ($user) {
            if ((int) $user['is_active'] !== 1) {
                if ($user['role'] !== 'resident') {
                    $this->api->respond_error('Account is inactive.', 403);
                }
                if ($intent !== 'reactivate') {
                    $this->api->respond_error('This account is deactivated. Confirm reactivation to continue.', 403);
                }
                if (!$this->db->transaction()) {
                    $this->api->respond_error('Could not reactivate the account. Please try again.', 500);
                }
                try {
                    $this->db->raw('UPDATE users SET is_active = 1, updated_at = NOW() WHERE id = ?', [$user['id']]);
                    $this->actor = $user;
                    $this->audit('reactivated', 'users', $user['id'], 'Resident reactivated their account with Google.');
                    $this->db->commit();
                } catch (Throwable $error) {
                    $this->db->roll_back();
                    throw $error;
                }
                $user['is_active'] = 1;
            }
            $this->db->raw(
                'UPDATE users SET password_is_set = COALESCE(password_is_set, 0) WHERE id = ?',
                [$user['id']]
            );
            if (empty($user['email_verified_at'])) {
                $this->db->raw(
                    'UPDATE users SET email_verified_at = NOW(), updated_at = NOW() WHERE id = ?',
                    [$user['id']]
                );
            }
            $this->db->raw('DELETE FROM email_verification_tokens WHERE user_id = ?', [$user['id']]);
            $user = $this->getUser($user['id']);
        } else {
            if (!$this->db->transaction()) {
                $this->api->respond_error('Could not start Google account registration. Please try again.', 500);
            }
            try {
                $name = trim((string) ($identity['name'] ?? ''));
                if ($name === '') $name = strstr($email, '@', true) ?: 'Baco360 Resident';
                $name = substr($name, 0, 150);
                $this->db->raw(
                    'INSERT INTO users (name, email, phone, password, password_is_set, role, is_active, email_verified_at, created_at, updated_at)
                     VALUES (?, ?, NULL, ?, 0, ?, 1, NOW(), NOW(), NOW())',
                    [$name, $email, password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT), 'resident']
                );
                $user = $this->getUserByEmail($email);
                if (!$user) throw new RuntimeException('Google account was created but could not be loaded.');
                $this->db->raw(
                    'INSERT INTO notification_settings (user_id, sms_enabled, email_enabled, report_updates_enabled, resolution_updates_enabled)
                     VALUES (?, 0, 1, 1, 1)',
                    [$user['id']]
                );
                $this->db->commit();
                $accountCreated = true;
            } catch (Throwable $error) {
                $this->db->roll_back();
                $user = $this->getUserByEmail($email);
                if (!$user) {
                    error_log('Could not create Google account: ' . $error->getMessage());
                    $this->api->respond_error('Could not create the Google account. Please try again.', 500);
                }
                if ((int) $user['is_active'] !== 1) {
                    $this->api->respond_error('Account is inactive.', 403);
                }
                $this->db->raw(
                    'UPDATE users SET password_is_set = COALESCE(password_is_set, 0), email_verified_at = NOW(), updated_at = NOW() WHERE id = ?',
                    [$user['id']]
                );
                $user = $this->getUser($user['id']);
            }
        }

        $welcomeEmailSent = null;
        if ($accountCreated) {
            try {
                SmtpMailer::sendWelcomeEmail($email, (string) $user['name']);
                $welcomeEmailSent = true;
            } catch (Throwable $error) {
                $welcomeEmailSent = false;
                error_log('Could not send Google account welcome email for user ' . $user['id'] . ': ' . $error->getMessage());
            }
        }

        $authVersion = $this->db->raw(
            'SELECT auth_version FROM users WHERE id = ? LIMIT 1',
            [$user['id']]
        )->fetchColumn();
        $tokens = $this->api->issue_tokens([
            'id' => $user['id'],
            'role' => $user['role'],
            'auth_version' => (int) $authVersion,
        ]);
        $this->actor = $user;
        $this->audit('login', 'auth', $user['id'], 'Signed in with Google.');
        $response = [
            'user' => $this->userWithSettings($user),
            'tokens' => $tokens,
        ];
        if ($accountCreated) {
            $response['account_created'] = true;
            $response['welcome_email_sent'] = $welcomeEmailSent;
        }
        $this->respondSuccess($response, 'Google sign-in successful.');
    }

    private function verifyGoogleIdToken($idToken, $clientId)
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 8,
                'ignore_errors' => true,
                'header' => "Accept: application/json\r\n",
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);
        $url = 'https://oauth2.googleapis.com/tokeninfo?id_token=' . rawurlencode($idToken);
        $response = @file_get_contents($url, false, $context);
        if ($response === false) {
            error_log('Google token verification request failed.');
            $this->api->respond_error('Google sign-in is temporarily unavailable. Please try again.', 503);
        }

        $identity = json_decode($response, true);
        if (!is_array($identity)
            || !in_array($identity['iss'] ?? '', ['accounts.google.com', 'https://accounts.google.com'], true)
            || !hash_equals($clientId, (string) ($identity['aud'] ?? ''))
            || (isset($identity['azp']) && !hash_equals($clientId, (string) $identity['azp']))
            || (int) ($identity['exp'] ?? 0) <= time()
            || !in_array($identity['email_verified'] ?? false, [true, 'true', 1, '1'], true)
            || !is_string($identity['email'] ?? null)
            || !is_string($identity['sub'] ?? null)
            || $identity['sub'] === '') {
            return null;
        }

        return $identity;
    }

    public function me()
    {
        $this->respondSuccess($this->userWithSettings($this->authenticate()));
    }

    public function loginHistory()
    {
        $this->api->require_method('GET');
        $actor = $this->authenticate();
        $logs = $this->db->raw(
            'SELECT id, description, ip_address, user_agent, created_at
             FROM audit_logs
             WHERE user_id = ? AND action = ? AND entity_type = ?
             ORDER BY created_at DESC, id DESC
             LIMIT 50',
            [$actor['id'], 'login', 'auth']
        )->fetchAll(PDO::FETCH_ASSOC);

        $this->respondSuccess(['logs' => $logs]);
    }

    public function activeSessions()
    {
        $this->api->require_method('GET');
        $actor = $this->authenticate();
        $currentSessionId = $this->sessionId;

        if (!$currentSessionId) {
            $refreshToken = $_SERVER['HTTP_X_REFRESH_TOKEN'] ?? '';
            $refreshPayload = is_string($refreshToken) && $refreshToken !== ''
                ? $this->api->validate_jwt($refreshToken, 'refresh')
                : null;
            if ($refreshPayload && (int) ($refreshPayload['sub'] ?? 0) === (int) $actor['id'] && !empty($refreshPayload['jti'])) {
                $currentSessionId = $this->db->raw(
                    'SELECT session_id FROM refresh_tokens
                     WHERE user_id = ? AND jti = ? AND expires_at > NOW()
                     LIMIT 1',
                    [$actor['id'], $refreshPayload['jti']]
                )->fetchColumn();
                if ($currentSessionId === false) $currentSessionId = null;
            }
        }

        $sessions = $this->db->raw(
            'SELECT session_id, created_at, expires_at, ip_address, user_agent
             FROM refresh_tokens
             WHERE user_id = ? AND expires_at > NOW()
             ORDER BY COALESCE(created_at, expires_at) DESC',
            [$actor['id']]
        )->fetchAll(PDO::FETCH_ASSOC);
        foreach ($sessions as &$session) {
            $session['is_current'] = is_string($currentSessionId)
                && hash_equals($currentSessionId, (string) $session['session_id']);
        }
        unset($session);

        $this->respondSuccess(['sessions' => $sessions]);
    }

    public function revokeSession($sessionId)
    {
        $this->api->require_method('DELETE');
        $actor = $this->authenticate();
        if (!is_string($sessionId) || preg_match('/\A[a-f0-9]{32}\z/', $sessionId) !== 1) {
            $this->api->respond_error('Invalid session identifier.', 422);
        }

        $deleted = $this->db->raw(
            'DELETE FROM refresh_tokens WHERE user_id = ? AND session_id = ?',
            [$actor['id'], $sessionId]
        );
        if ($deleted->rowCount() === 0) {
            $this->api->respond_error('Active session not found.', 404);
        }

        $this->respondSuccess(null, 'Session revoked.');
    }

    public function updateProfile()
    {
        $this->api->require_method('PUT');
        $actor = $this->authenticate();
        $input = $this->api->body();
        $fields = [];
        $values = [];

        if ($actor['role'] === 'resident' && (array_key_exists('email', $input) || array_key_exists('phone', $input))) {
            $currentUser = $this->getUser($actor['id']);
            $emailChanged = array_key_exists('email', $input)
                && strtolower(trim((string) $input['email'])) !== strtolower((string) $currentUser['email']);
            $requestedPhone = array_key_exists('phone', $input) ? trim((string) $input['phone']) : (string) ($currentUser['phone'] ?? '');
            $phoneChanged = array_key_exists('phone', $input)
                && ($requestedPhone ?: null) !== ($currentUser['phone'] !== null ? (string) $currentUser['phone'] : null);
            if ($emailChanged || $phoneChanged) {
                $this->api->respond_error('Email and phone changes require verification. Use the contact verification flow.', 422);
            }
        }

        foreach (['name' => 150, 'phone' => 30, 'email' => 150] as $field => $maxLength) {
            if (!array_key_exists($field, $input)) continue;
            $value = trim((string) $input[$field]);
            if ($field === 'email') $value = strtolower($value);
            if ($value === '' && $field !== 'phone') {
                $this->api->respond_error(ucfirst($field) . ' cannot be empty.', 422);
            }
            if (strlen($value) > $maxLength || ($field === 'email' && !filter_var($value, FILTER_VALIDATE_EMAIL))) {
                $this->api->respond_error('Invalid ' . $field . '.', 422);
            }
            $fields[] = $field . ' = ?';
            $values[] = $value ?: null;
        }
        if (!$fields) $this->api->respond_error('No profile fields were provided.', 422);

        $values[] = $actor['id'];
        try {
            $this->db->raw('UPDATE users SET ' . implode(', ', $fields) . ', updated_at = NOW() WHERE id = ?', $values);
        } catch (PDOException $error) {
            if ($error->getCode() === '23000') $this->api->respond_error('That email address is already in use.', 409);
            throw $error;
        }
        $this->respondSuccess($this->userWithSettings($this->getUser($actor['id'])), 'Profile updated.');
    }

    public function requestContactChange()
    {
        $this->api->require_method('POST');
        $actor = $this->authenticate();
        $input = $this->api->body();
        $user = $this->getUser($actor['id']);
        $email = strtolower(trim((string) ($input['email'] ?? '')));
        $phone = trim((string) ($input['phone'] ?? ''));
        $phone = $phone === '' ? null : $phone;

        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 150) {
            $this->api->respond_error('Enter a valid email address.', 422);
        }
        if ($phone !== null && strlen($phone) > 30) {
            $this->api->respond_error('Phone number must be 30 characters or fewer.', 422);
        }

        $emailChanged = $email !== strtolower((string) $user['email']);
        $phoneChanged = $phone !== ($user['phone'] !== null ? (string) $user['phone'] : null);
        if (!$emailChanged && !$phoneChanged) {
            $this->api->respond_error('No contact details have changed.', 422);
        }
        if ($emailChanged && $this->db->raw(
            'SELECT id FROM users WHERE email = ? AND id <> ? LIMIT 1',
            [$email, $actor['id']]
        )->fetch(PDO::FETCH_ASSOC)) {
            $this->api->respond_error('That email address is already in use.', 409);
        }

        if (!$phoneChanged) {
            if (!$this->db->transaction()) {
                $this->api->respond_error('Could not update your email. Please try again.', 500);
            }
            try {
                $this->db->raw('UPDATE users SET email = ?, updated_at = NOW() WHERE id = ?', [$email, $actor['id']]);
                $this->db->raw('DELETE FROM user_contact_change_tokens WHERE user_id = ?', [$actor['id']]);
                $this->db->commit();
            } catch (PDOException $error) {
                $this->db->roll_back();
                if ($error->getCode() === '23000') $this->api->respond_error('That email address is already in use.', 409);
                throw $error;
            } catch (Throwable $error) {
                $this->db->roll_back();
                throw $error;
            }

            $this->respondSuccess([
                'email_verification_required' => false,
                'phone_verification_required' => false,
                'user' => $this->userWithSettings($this->getUser($actor['id'])),
            ], 'Email updated successfully.');
        }

        if (empty($user['email_verified_at'])) {
            $this->api->respond_error('Verify your current email before changing your phone number.', 403);
        }
        if (!SmtpMailer::isConfigured()) {
            $this->api->respond_error('Email verification is not configured. Phone numbers cannot be changed yet.', 503);
        }

        $existingRequest = $this->db->raw(
            'SELECT sent_at, (sent_at > DATE_SUB(NOW(), INTERVAL 60 SECOND)) AS sent_recently
             FROM user_contact_change_tokens WHERE user_id = ? LIMIT 1',
            [$actor['id']]
        )->fetch(PDO::FETCH_ASSOC);
        if ($existingRequest && (int) $existingRequest['sent_recently'] === 1) {
            $this->api->respond_error('Please wait a minute before requesting another verification code.', 429);
        }

        $accountCode = $phoneChanged ? str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT) : null;
        if (!$this->db->transaction()) {
            $this->api->respond_error('Could not start contact verification. Please try again.', 500);
        }
        try {
            if ($emailChanged) {
                $this->db->raw('UPDATE users SET email = ?, updated_at = NOW() WHERE id = ?', [$email, $actor['id']]);
            }
            $this->db->raw(
                'INSERT INTO user_contact_change_tokens
                    (user_id, pending_email, pending_phone, phone_change_requested, account_code_hash, email_code_hash, expires_at, sent_at, attempts)
                 VALUES (?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 15 MINUTE), NOW(), 0)
                 ON DUPLICATE KEY UPDATE
                    pending_email = VALUES(pending_email),
                    pending_phone = VALUES(pending_phone),
                    phone_change_requested = VALUES(phone_change_requested),
                    account_code_hash = VALUES(account_code_hash),
                    email_code_hash = VALUES(email_code_hash),
                    expires_at = VALUES(expires_at),
                    sent_at = NOW(),
                    attempts = 0',
                [
                    $actor['id'],
                    null,
                    $phoneChanged ? $phone : null,
                    1,
                    hash('sha256', $accountCode),
                    null,
                ]
            );
            SmtpMailer::sendAccountChangeCode($user['email'], $user['name'], $accountCode, 'account');
            $this->db->commit();
        } catch (PDOException $error) {
            $this->db->roll_back();
            if ($error->getCode() === '23000') $this->api->respond_error('That email address is already in use.', 409);
            error_log('Could not send profile contact verification: ' . $error->getMessage());
            $this->api->respond_error('The verification email could not be sent. Check the MAIL_* SMTP configuration and try again later.', 502);
        } catch (Throwable $error) {
            $this->db->roll_back();
            error_log('Could not send profile contact verification: ' . $error->getMessage());
            $this->api->respond_error('The verification email could not be sent. Check the MAIL_* SMTP configuration and try again later.', 502);
        }

        $this->respondSuccess([
            'email_verification_required' => false,
            'phone_verification_required' => $phoneChanged,
            'user' => $this->userWithSettings($this->getUser($actor['id'])),
        ], $emailChanged
            ? 'Email updated. A code was sent to your previous email to verify the phone change.'
            : 'A verification code was sent to your current email.');
    }

    public function verifyContactChange()
    {
        $this->api->require_method('POST');
        $actor = $this->authenticate();
        $input = $this->api->body();
        $accountCode = trim((string) ($input['account_code'] ?? ''));
        $emailCode = trim((string) ($input['email_code'] ?? ''));
        $pending = $this->db->raw(
            'SELECT pending_email, pending_phone, phone_change_requested, account_code_hash, email_code_hash, attempts,
                    (expires_at > NOW()) AS code_is_valid
             FROM user_contact_change_tokens WHERE user_id = ? LIMIT 1',
            [$actor['id']]
        )->fetch(PDO::FETCH_ASSOC);

        if (!$pending || (int) $pending['code_is_valid'] !== 1) {
            $this->api->respond_error('The verification codes have expired or are no longer active. Request new codes.', 422);
        }
        if ((int) $pending['attempts'] >= 5) {
            $this->api->respond_error('Too many incorrect codes. Request new verification codes.', 429);
        }
        $accountValid = (int) $pending['phone_change_requested'] !== 1
            || (preg_match('/^\d{6}$/', $accountCode)
                && hash_equals($pending['account_code_hash'], hash('sha256', $accountCode)));
        $emailValid = $pending['email_code_hash'] === null
            || (preg_match('/^\d{6}$/', $emailCode) && hash_equals($pending['email_code_hash'], hash('sha256', $emailCode)));
        if (!$accountValid || !$emailValid) {
            $this->db->raw(
                'UPDATE user_contact_change_tokens SET attempts = attempts + 1 WHERE user_id = ?',
                [$actor['id']]
            );
            $this->api->respond_error('One or more verification codes are incorrect.', 422);
        }

        if ($pending['pending_email'] !== null && $this->db->raw(
            'SELECT id FROM users WHERE email = ? AND id <> ? LIMIT 1',
            [$pending['pending_email'], $actor['id']]
        )->fetch(PDO::FETCH_ASSOC)) {
            $this->api->respond_error('That email address is already in use. Request new codes after choosing another address.', 409);
        }

        $fields = [];
        $values = [];
        if ($pending['pending_email'] !== null) {
            $fields[] = 'email = ?';
            $fields[] = 'email_verified_at = NOW()';
            $values[] = $pending['pending_email'];
        }
        if ((int) $pending['phone_change_requested'] === 1) {
            $fields[] = 'phone = ?';
            $values[] = $pending['pending_phone'];
        }
        $values[] = $actor['id'];

        if (!$this->db->transaction()) {
            $this->api->respond_error('Could not save your contact changes. Please try again.', 500);
        }
        try {
            $this->db->raw(
                'UPDATE users SET ' . implode(', ', $fields) . ', updated_at = NOW() WHERE id = ?',
                $values
            );
            $this->db->raw('DELETE FROM user_contact_change_tokens WHERE user_id = ?', [$actor['id']]);
            $this->db->commit();
        } catch (PDOException $error) {
            $this->db->roll_back();
            if ($error->getCode() === '23000') {
                $this->api->respond_error('That email address is already in use.', 409);
            }
            throw $error;
        } catch (Throwable $error) {
            $this->db->roll_back();
            throw $error;
        }

        $this->respondSuccess($this->userWithSettings($this->getUser($actor['id'])), 'Contact details verified and updated.');
    }

    public function changePassword()
    {
        $this->api->require_method('PUT');
        $actor = $this->authenticate();
        $input = $this->api->body();
        $currentPassword = $input['current_password'] ?? '';
        $password = $input['password'] ?? null;
        $confirmation = $input['password_confirmation'] ?? null;
        if (!is_string($currentPassword) || !is_string($password) || strlen($password) < 8 || $password !== $confirmation) {
            $this->api->respond_error('Provide a matching new password of at least 8 characters.', 422);
        }

        $user = $this->db->raw(
            'SELECT password, password_is_set FROM users WHERE id = ?',
            [$actor['id']]
        )->fetch(PDO::FETCH_ASSOC);
        if (!$user) {
            $this->api->respond_error('Account not found.', 404);
        }
        $hasLocalPassword = $user['password_is_set'] === null || (int) $user['password_is_set'] !== 0;
        if ($hasLocalPassword && ($currentPassword === '' || !password_verify($currentPassword, $user['password']))) {
            $this->api->respond_error('Your current password is required and must be correct.', 422);
        }

        $this->db->raw(
            'UPDATE users SET password = ?, password_is_set = 1, updated_at = NOW() WHERE id = ?',
            [password_hash($password, PASSWORD_DEFAULT), $actor['id']]
        );
        $this->respondSuccess(null, 'Password changed successfully.');
    }

    public function deactivateOwnAccount()
    {
        $this->api->require_method('POST');
        $actor = $this->authenticate();
        if ($actor['role'] !== 'resident') {
            $this->api->respond_error('Only residents can deactivate their own account here.', 403);
        }

        $input = $this->api->body();
        $reason = $input['reason'] ?? '';
        $details = $input['reason_details'] ?? '';
        $reasonLabels = [
            'no_longer_needed' => 'I no longer need the account',
            'taking_a_break' => 'I am taking a break',
            'privacy_concerns' => 'Privacy concerns',
            'too_many_notifications' => 'Too many notifications',
            'difficulty_using_app' => 'Difficulty using Baco360',
            'other' => 'Other',
        ];
        if (!is_string($reason) || !array_key_exists($reason, $reasonLabels)
            || !is_string($details) || strlen($details) > 500) {
            $this->api->respond_error('Choose a valid deactivation reason.', 422);
        }
        $details = trim($details);
        if ($reason === 'other' && $details === '') {
            $this->api->respond_error('Please explain your reason for deactivating the account.', 422);
        }
        $reasonDescription = $reasonLabels[$reason] . ($details !== '' ? ': ' . $details : '');

        if (!$this->db->transaction()) {
            $this->api->respond_error('Could not deactivate the account. Please try again.', 500);
        }
        try {
            $this->db->raw(
                'UPDATE users SET is_active = 0, auth_version = auth_version + 1, updated_at = NOW() WHERE id = ?',
                [$actor['id']]
            );
            $this->db->raw('DELETE FROM refresh_tokens WHERE user_id = ?', [$actor['id']]);
            $this->actor = $actor;
            $this->audit('deactivated', 'users', $actor['id'], 'Resident deactivated their account. Reason: ' . $reasonDescription);
            $this->db->commit();
        } catch (Throwable $error) {
            $this->db->roll_back();
            throw $error;
        }

        $this->respondSuccess(null, 'Account deactivated. Sign in again to reactivate it.');
    }

    public function deleteOwnAccount()
    {
        $this->api->require_method('DELETE');
        $actor = $this->authenticate();
        if ($actor['role'] !== 'resident') {
            $this->api->respond_error('Only residents can delete their own account here.', 403);
        }

        $input = $this->api->body();
        $password = $input['password'] ?? null;
        if (!is_string($password) || $password === '' || strlen($password) > 1024) {
            $this->api->respond_error('Enter your password to delete the account.', 422);
        }
        if (!$this->db->transaction()) {
            $this->api->respond_error('Could not delete the account. Please try again.', 500);
        }

        try {
            $user = $this->db->raw(
                'SELECT password, password_is_set, profile_photo FROM users WHERE id = ? FOR UPDATE',
                [$actor['id']]
            )->fetch(PDO::FETCH_ASSOC);
            if (!$user) {
                $this->db->roll_back();
                $this->api->respond_error('Account not found.', 404);
            }
            if ((int) $user['password_is_set'] !== 1) {
                $this->db->roll_back();
                $this->api->respond_error('Set a password in Account Settings before deleting your Google account.', 422);
            }
            if (!password_verify($password, $user['password'])) {
                $this->db->roll_back();
                $this->api->respond_error('Your password is incorrect.', 422);
            }

            $references = [
                'reports' => 'resident_id',
                'report_comments' => 'user_id',
                'report_assignments' => 'staff_id',
                'community_report_comments' => 'user_id',
                'community_report_reactions' => 'user_id',
                'community_events' => 'created_by',
                'announcements' => 'created_by',
            ];
            foreach ($references as $table => $column) {
                $count = $this->db->raw(
                    'SELECT COUNT(*) FROM ' . $table . ' WHERE ' . $column . ' = ?',
                    [$actor['id']]
                )->fetchColumn();
                if ((int) $count > 0) {
                    $this->db->roll_back();
                    $this->api->respond_error('This account has linked community records and cannot be deleted. Deactivate it instead.', 409);
                }
            }

            $this->deleteStoredProfilePhoto($user['profile_photo'] ?? null);
            foreach (['email_verification_tokens', 'password_reset_tokens', 'user_contact_change_tokens', 'notification_settings', 'resident_profiles'] as $table) {
                $this->db->raw('DELETE FROM ' . $table . ' WHERE user_id = ?', [$actor['id']]);
            }
            $this->db->raw('DELETE FROM user_notifications WHERE recipient_id = ?', [$actor['id']]);
            $this->db->raw('UPDATE user_notifications SET actor_id = NULL WHERE actor_id = ?', [$actor['id']]);
            $this->db->raw('DELETE FROM refresh_tokens WHERE user_id = ?', [$actor['id']]);
            $this->db->raw('DELETE FROM users WHERE id = ?', [$actor['id']]);
            $this->db->commit();
        } catch (Throwable $error) {
            $this->db->roll_back();
            throw $error;
        }

        $this->respondSuccess(null, 'Account deleted.');
    }

    private function deleteStoredProfilePhoto($path)
    {
        if (!is_string($path) || preg_match('/\Aprofile-photos\/[a-f0-9]{32}\.(jpg|png|webp)\z/', $path) !== 1) {
            return;
        }
        $filePath = ROOT_DIR . 'runtime/uploads/' . $path;
        if (is_file($filePath) && !unlink($filePath)) {
            throw new RuntimeException('Unable to remove the account profile photo.');
        }
    }

    public function updateNotificationSettings()
    {
        $this->api->require_method('PUT');
        $actor = $this->authenticate();
        $input = $this->api->body();
        $allowed = ['sms_enabled', 'email_enabled', 'report_updates_enabled', 'resolution_updates_enabled'];
        $settings = $this->getNotificationSettings($actor['id']);
        foreach ($allowed as $key) {
            if (array_key_exists($key, $input)) $settings[$key] = !empty($input[$key]) ? 1 : 0;
        }
        $this->db->raw(
            'INSERT INTO notification_settings (user_id, sms_enabled, email_enabled, report_updates_enabled, resolution_updates_enabled)
             VALUES (?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE sms_enabled = VALUES(sms_enabled), email_enabled = VALUES(email_enabled),
                report_updates_enabled = VALUES(report_updates_enabled), resolution_updates_enabled = VALUES(resolution_updates_enabled),
                updated_at = NOW()',
            [$actor['id'], $settings['sms_enabled'], $settings['email_enabled'], $settings['report_updates_enabled'], $settings['resolution_updates_enabled']]
        );
        $this->respondSuccess($this->userWithSettings($this->getUser($actor['id'])), 'Notification settings updated.');
    }

    public function logout()
    {
        $this->api->require_method('POST');
        $actor = $this->authenticate();
        $input = $this->api->body();
        $refreshToken = $input['refresh_token'] ?? '';
        $refreshPayload = null;
        if ($refreshToken !== '' && $refreshToken !== null) {
            $refreshPayload = is_string($refreshToken) ? $this->api->validate_jwt($refreshToken, 'refresh') : null;
            if (!$refreshPayload || (int) ($refreshPayload['sub'] ?? 0) !== (int) $actor['id']
                || ($this->sessionId !== null && !hash_equals($this->sessionId, (string) ($refreshPayload['session_id'] ?? '')))) {
                $this->api->respond_error('Invalid refresh token for this session.', 403);
            }
        }
        $sessionIdToRevoke = $this->sessionId ?? ($refreshPayload['session_id'] ?? null);
        if (is_string($sessionIdToRevoke)) {
            $this->db->raw(
                'DELETE FROM refresh_tokens WHERE user_id = ? AND session_id = ?',
                [$actor['id'], $sessionIdToRevoke]
            );
        } elseif ($refreshPayload && !empty($refreshPayload['jti'])) {
            $this->db->raw(
                'DELETE FROM refresh_tokens WHERE user_id = ? AND jti = ?',
                [$actor['id'], $refreshPayload['jti']]
            );
        }
        $this->respondSuccess(null, 'Logged out successfully.');
    }

    public function refresh()
    {
        $this->api->require_method('POST');
        $input = $this->api->body();
        $refreshToken = $input['refresh_token'] ?? '';
        if (!is_string($refreshToken) || $refreshToken === '') {
            $this->api->respond_error('A refresh token is required.', 400);
        }
        $this->api->refresh_access_token($refreshToken);
    }

    private function codeTiming($existingRequest = null)
    {
        if ($existingRequest) {
            return [
                'expires_in_seconds' => max(0, (int) $existingRequest['expires_in_seconds']),
                'resend_after_seconds' => max(0, (int) $existingRequest['resend_after_seconds']),
            ];
        }

        return [
            'expires_in_seconds' => self::ONE_TIME_CODE_TTL_SECONDS,
            'resend_after_seconds' => self::ONE_TIME_CODE_RESEND_DELAY_SECONDS,
        ];
    }

    private function hashOneTimeCode($code)
    {
        $secret = (string) config_item('jwt_secret');
        if ($secret === '') {
            throw new RuntimeException('The JWT secret is not configured for one-time code hashing.');
        }
        $codeHashKey = hash_hmac('sha256', 'baco360-one-time-code-hash', $secret, true);
        return hash_hmac('sha256', $code, $codeHashKey);
    }

    private function getUserByEmail($email)
    {
        return $this->db->raw(
            'SELECT id, name, email, phone, role, is_active, email_verified_at, profile_photo, created_at
             FROM users WHERE email = ? LIMIT 1',
            [$email]
        )->fetch(PDO::FETCH_ASSOC);
    }

    private function userWithSettings($user)
    {
        $passwordIsSet = $this->db->raw(
            'SELECT password_is_set FROM users WHERE id = ? LIMIT 1',
            [$user['id']]
        )->fetchColumn();
        $user['has_password'] = $passwordIsSet === false || $passwordIsSet === null
            ? true
            : (int) $passwordIsSet === 1;
        $user['notification_settings'] = $this->getNotificationSettings($user['id']);
        return $this->withProfilePhotoUrl($user);
    }
}
