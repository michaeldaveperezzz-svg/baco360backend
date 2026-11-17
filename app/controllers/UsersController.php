<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');
require_once __DIR__ . '/ApiBaseController.php';

class UsersController extends ApiBaseController
{
    public function index()
    {
        $this->requireAdmin();
        $sql = 'SELECT id, name, email, phone, role, is_active, email_verified_at, profile_photo, created_at FROM users';
        $conditions = [];
        $values = [];
        if (!empty($_GET['role']) && in_array($_GET['role'], ['resident', 'staff', 'admin'], true)) {
            $conditions[] = 'role = ?';
            $values[] = $_GET['role'];
        }
        if (isset($_GET['is_active']) && $_GET['is_active'] !== '') {
            $conditions[] = 'is_active = ?';
            $values[] = filter_var($_GET['is_active'], FILTER_VALIDATE_BOOLEAN) ? 1 : 0;
        }
        if ($conditions) $sql .= ' WHERE ' . implode(' AND ', $conditions);
        $sql .= ' ORDER BY created_at DESC, id DESC';
        $users = $this->db->raw($sql, $values)->fetchAll(PDO::FETCH_ASSOC);
        foreach ($users as &$user) {
            $user['notification_settings'] = $this->getNotificationSettings($user['id']);
            $user = $this->withProfilePhotoUrl($user);
        }
        unset($user);
        $this->respondSuccess(['users' => $users]);
    }

    public function show($id)
    {
        $this->requireAdmin();
        $user = $this->getUser($id);
        if (!$user) $this->api->respond_error('User not found.', 404);
        $user['notification_settings'] = $this->getNotificationSettings($id);
        $this->respondSuccess($this->withProfilePhotoUrl($user));
    }

    public function store()
    {
        $this->api->require_method('POST');
        $actor = $this->requireAdmin();
        $input = $this->api->body();
        $name = trim($input['name'] ?? '');
        $email = strtolower(trim($input['email'] ?? ''));
        $phone = trim($input['phone'] ?? '');
        $role = $input['role'] ?? 'resident';
        $password = $input['password'] ?? '';

        if ($name === '' || strlen($name) > 150 || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 150) {
            $this->api->respond_error('Enter a valid name and email address.', 422);
        }
        if (!in_array($role, ['resident', 'staff', 'admin'], true)) {
            $this->api->respond_error('Choose a valid user role.', 422);
        }
        if (!is_string($password) || strlen($password) < 8) {
            $this->api->respond_error('The password must contain at least 8 characters.', 422);
        }
        if ($this->db->raw('SELECT id FROM users WHERE email = ? LIMIT 1', [$email])->fetch(PDO::FETCH_ASSOC)) {
            $this->api->respond_error('An account with this email already exists.', 409);
        }

        $this->db->raw(
            'INSERT INTO users (name, email, phone, password, password_is_set, role, is_active, created_at, updated_at)
             VALUES (?, ?, ?, ?, 1, ?, 1, NOW(), NOW())',
            [$name, $email, $phone ?: null, password_hash($password, PASSWORD_DEFAULT), $role]
        );
        $id = $this->db->raw('SELECT LAST_INSERT_ID()')->fetchColumn();
        $this->db->raw(
            'INSERT INTO notification_settings (user_id, sms_enabled, email_enabled, report_updates_enabled, resolution_updates_enabled)
             VALUES (?, ?, ?, 1, 1)',
            [
                $id,
                !array_key_exists('sms_enabled', $input) || !empty($input['sms_enabled']) ? 1 : 0,
                !array_key_exists('email_enabled', $input) || !empty($input['email_enabled']) ? 1 : 0,
            ]
        );
        $this->actor = $actor;
        $this->audit('created', 'users', $id, 'Created user account ' . $email);
        $user = $this->getUser($id);
        $user['notification_settings'] = $this->getNotificationSettings($id);
        $this->respondSuccess($this->withProfilePhotoUrl($user), 'User created.', 201);
    }

    public function update($id)
    {
        $this->api->require_method('PUT');
        $actor = $this->requireAdmin();
        $user = $this->getUser($id);
        if (!$user) $this->api->respond_error('User not found.', 404);
        $input = $this->api->body();
        $fields = [];
        $values = [];

        foreach (['name' => 150, 'email' => 150, 'phone' => 30] as $field => $maxLength) {
            if (!array_key_exists($field, $input)) continue;
            $value = trim((string) $input[$field]);
            if ($field === 'email') $value = strtolower($value);
            if ($field !== 'phone' && $value === '') $this->api->respond_error(ucfirst($field) . ' cannot be empty.', 422);
            if (strlen($value) > $maxLength || ($field === 'email' && !filter_var($value, FILTER_VALIDATE_EMAIL))) {
                $this->api->respond_error('Invalid ' . $field . '.', 422);
            }
            $fields[] = $field . ' = ?';
            $values[] = $value ?: null;
        }

        if (isset($input['role'])) {
            if (!in_array($input['role'], ['resident', 'staff', 'admin'], true)) {
                $this->api->respond_error('Choose a valid user role.', 422);
            }
            if ((int) $id === (int) $actor['id'] && $input['role'] !== 'admin') {
                $this->api->respond_error('You cannot remove your own administrator role.', 409);
            }
            $fields[] = 'role = ?';
            $values[] = $input['role'];
        }
        if (array_key_exists('is_active', $input)) {
            $active = filter_var($input['is_active'], FILTER_VALIDATE_BOOLEAN) ? 1 : 0;
            if ((int) $id === (int) $actor['id'] && !$active) {
                $this->api->respond_error('You cannot deactivate your own account.', 409);
            }
            $fields[] = 'is_active = ?';
            $values[] = $active;
            if (!$active && (int) $user['is_active'] === 1) {
                $fields[] = 'auth_version = auth_version + 1';
                $this->db->raw('DELETE FROM refresh_tokens WHERE user_id = ?', [$id]);
            }
        }
        if (array_key_exists('password', $input) && $input['password'] !== '') {
            if (!is_string($input['password']) || strlen($input['password']) < 8) {
                $this->api->respond_error('The password must contain at least 8 characters.', 422);
            }
            $fields[] = 'password = ?';
            $values[] = password_hash($input['password'], PASSWORD_DEFAULT);
            $fields[] = 'password_is_set = 1';
        }
        if (!$fields) $this->api->respond_error('No user changes were provided.', 422);

        if ((int) $id !== (int) $actor['id'] && $user['role'] === 'admin'
            && (($input['role'] ?? 'admin') !== 'admin' || (isset($input['is_active']) && !filter_var($input['is_active'], FILTER_VALIDATE_BOOLEAN)))) {
            $remaining = $this->db->raw(
                'SELECT COUNT(*) AS total FROM users WHERE role = ? AND is_active = 1 AND id <> ?',
                ['admin', $id]
            )->fetch(PDO::FETCH_ASSOC);
            if ((int) $remaining['total'] === 0) $this->api->respond_error('At least one active administrator must remain.', 409);
        }

        $values[] = $id;
        try {
            $this->db->raw('UPDATE users SET ' . implode(', ', $fields) . ', updated_at = NOW() WHERE id = ?', $values);
        } catch (PDOException $error) {
            if ($error->getCode() === '23000') $this->api->respond_error('That email address is already in use.', 409);
            throw $error;
        }
        if (isset($input['role']) && $input['role'] !== 'resident' && $user['role'] === 'resident') {
            $this->db->raw('DELETE FROM resident_profiles WHERE user_id = ?', [$id]);
        }
        $this->actor = $actor;
        $this->audit('updated', 'users', $id, 'Updated user account ' . $id);
        $updated = $this->getUser($id);
        $updated['notification_settings'] = $this->getNotificationSettings($id);
        $this->respondSuccess($this->withProfilePhotoUrl($updated), 'User updated.');
    }

    public function destroy($id)
    {
        $this->api->require_method('DELETE');
        $actor = $this->requireAdmin();
        $input = $this->api->body();
        $deleteLinkedReports = filter_var($input['delete_linked_reports'] ?? false, FILTER_VALIDATE_BOOLEAN);
        if (!$this->db->transaction()) {
            $this->api->respond_error('Could not delete the account. Please try again.', 500);
        }

        $reportAttachmentPaths = [];
        $profilePhoto = null;
        $reportCount = 0;
        try {
            $user = $this->db->raw(
                'SELECT id, role, is_active, profile_photo FROM users WHERE id = ? FOR UPDATE',
                [$id]
            )->fetch(PDO::FETCH_ASSOC);
            if (!$user) {
                $this->db->roll_back();
                $this->api->respond_error('User not found.', 404);
            }
            if ((int) $id === (int) $actor['id']) {
                $this->db->roll_back();
                $this->api->respond_error('You cannot delete your own account.', 409);
            }
            if ($user['role'] === 'admin') {
                $remaining = (int) $this->db->raw(
                    'SELECT COUNT(*) FROM users WHERE role = ? AND is_active = 1 AND id <> ?',
                    ['admin', $id]
                )->fetchColumn();
                if ($remaining === 0) {
                    $this->db->roll_back();
                    $this->api->respond_error('At least one active administrator must remain.', 409);
                }
            }

            $reportIds = array_map('intval', $this->db->raw(
                'SELECT id FROM reports WHERE resident_id = ? ORDER BY id FOR UPDATE',
                [$id]
            )->fetchAll(PDO::FETCH_COLUMN));
            $reportCount = count($reportIds);
            if ($reportCount > 0 && !$deleteLinkedReports) {
                $this->db->roll_back();
                $reportLabel = $reportCount === 1 ? 'report' : 'reports';
                $this->api->respond([
                    'error' => 'This account still has ' . $reportCount . ' ' . $reportLabel . '.',
                    'status' => 409,
                    'code' => 'USER_HAS_REPORTS',
                    'data' => ['report_count' => $reportCount],
                ], 409);
            }

            $assignmentCount = (int) $this->db->raw(
                'SELECT COUNT(*) FROM report_assignments
                 WHERE (staff_id = ? OR assigned_by = ?)
                   AND report_id NOT IN (SELECT id FROM reports WHERE resident_id = ?)',
                [$id, $id, $id]
            )->fetchColumn();
            if ($assignmentCount > 0) {
                $this->db->roll_back();
                $this->api->respond_error(
                    'This account is linked to ' . $assignmentCount . ' report assignments on other reports. Deactivate it instead of deleting it.',
                    409
                );
            }

            foreach ([
                'community_events' => ['created_by', 'community events'],
                'announcements' => ['created_by', 'announcements'],
            ] as $table => [$column, $recordLabel]) {
                $count = (int) $this->db->raw(
                    'SELECT COUNT(*) FROM ' . $table . ' WHERE ' . $column . ' = ?',
                    [$id]
                )->fetchColumn();
                if ($count > 0) {
                    $this->db->roll_back();
                    $this->api->respond_error(
                        'This account is linked to ' . $count . ' ' . $recordLabel . '. Deactivate it instead of deleting it.',
                        409
                    );
                }
            }

            $this->db->raw('UPDATE report_comments SET user_id = NULL WHERE user_id = ?', [$id]);
            $this->db->raw('UPDATE community_report_comments SET user_id = NULL WHERE user_id = ?', [$id]);
            $profilePhoto = $user['profile_photo'] ?? null;
            if ($reportIds) {
                $reportPlaceholders = implode(',', array_fill(0, $reportCount, '?'));
                $reportAttachmentPaths = $this->db->raw(
                    'SELECT file_path FROM report_attachments WHERE report_id IN (' . $reportPlaceholders . ')',
                    $reportIds
                )->fetchAll(PDO::FETCH_COLUMN);
                $reportFilter = ' IN (' . $reportPlaceholders . ')';

                $this->db->raw(
                    'DELETE FROM report_comment_attachments
                     WHERE comment_id IN (
                         SELECT id FROM report_comments WHERE report_id' . $reportFilter . '
                     )',
                    $reportIds
                );
                foreach ([
                    'community_report_comments',
                    'community_report_reactions',
                    'report_comments',
                    'report_assignments',
                    'report_status_histories',
                    'report_attachments',
                    'user_notifications',
                ] as $table) {
                    $this->db->raw(
                        'DELETE FROM ' . $table . ' WHERE report_id' . $reportFilter,
                        $reportIds
                    );
                }
                $this->db->raw(
                    'DELETE FROM reports WHERE id IN (' . $reportPlaceholders . ')',
                    $reportIds
                );
            }

            $this->db->raw('DELETE FROM community_report_reactions WHERE user_id = ?', [$id]);
            $this->db->raw('DELETE FROM email_verification_tokens WHERE user_id = ?', [$id]);
            $this->db->raw('DELETE FROM password_reset_tokens WHERE user_id = ?', [$id]);
            $this->db->raw('DELETE FROM user_contact_change_tokens WHERE user_id = ?', [$id]);
            $this->db->raw('DELETE FROM notification_settings WHERE user_id = ?', [$id]);
            $this->db->raw('DELETE FROM resident_profiles WHERE user_id = ?', [$id]);
            $this->db->raw('DELETE FROM announcement_recipients WHERE user_id = ?', [$id]);
            $this->db->raw('DELETE FROM user_notifications WHERE recipient_id = ?', [$id]);
            $this->db->raw('UPDATE user_notifications SET actor_id = NULL WHERE actor_id = ?', [$id]);
            $this->db->raw('DELETE FROM refresh_tokens WHERE user_id = ?', [$id]);
            $this->db->raw('DELETE FROM users WHERE id = ?', [$id]);
            $this->actor = $actor;
            $this->audit(
                'deleted',
                'users',
                $id,
                $reportCount > 0
                    ? 'Deleted user account ' . $id . ' and ' . $reportCount . ' linked report(s).'
                    : 'Deleted user account ' . $id
            );
            if (!$this->db->commit()) {
                throw new RuntimeException('Could not commit the account deletion.');
            }
        } catch (PDOException $error) {
            $this->db->roll_back();
            if ($error->getCode() === '23000') {
                $this->api->respond_error(
                    'This account still has linked records and cannot be deleted.',
                    409
                );
            }
            throw $error;
        } catch (Throwable $error) {
            $this->db->roll_back();
            throw $error;
        }

        $attachmentsDeleted = $this->deleteStoredReportAttachments($reportAttachmentPaths);
        $profilePhotoDeleted = $this->deleteStoredProfilePhoto($profilePhoto);
        $cleanupWarning = null;
        if (!$attachmentsDeleted || !$profilePhotoDeleted) {
            $cleanupWarning = 'The account and reports were deleted, but some uploaded files could not be removed.';
            error_log('Deleted user ' . $id . ' but could not remove all associated uploaded files.');
        }
        $this->respondSuccess(
            $cleanupWarning === null ? null : ['cleanup_warning' => $cleanupWarning],
            $reportCount > 0 ? 'User and linked reports deleted.' : 'User deleted.'
        );
    }

    private function deleteStoredReportAttachments(array $paths)
    {
        $directory = realpath(ROOT_DIR . 'runtime/uploads/reports');
        if ($directory === false) return true;

        $allDeleted = true;
        foreach ($paths as $path) {
            if (!is_string($path) || $path === '' || basename($path) !== $path) {
                $allDeleted = false;
                continue;
            }
            $filePath = realpath($directory . DIRECTORY_SEPARATOR . $path);
            if ($filePath === false) continue;
            if (dirname($filePath) !== $directory || !unlink($filePath)) {
                $allDeleted = false;
            }
        }
        return $allDeleted;
    }

    private function deleteStoredProfilePhoto($path)
    {
        if (!is_string($path) || preg_match('/\Aprofile-photos\/[a-f0-9]{32}\.(jpg|png|webp)\z/', $path) !== 1) {
            return true;
        }
        $uploadsDirectory = realpath(ROOT_DIR . 'runtime/uploads');
        if ($uploadsDirectory === false) return true;
        $filePath = realpath($uploadsDirectory . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $path));
        if ($filePath === false) return true;
        if (dirname($filePath) !== realpath($uploadsDirectory . DIRECTORY_SEPARATOR . 'profile-photos')) return false;
        return unlink($filePath);
    }
}
