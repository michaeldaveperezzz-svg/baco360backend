<?php

class Align_email_verification_user_id
{
    private $_lava;

    public function __construct()
    {
        $this->_lava = lava_instance();
        $this->_lava->call->dbforge();
    }

    public function up()
    {
        $userIdType = strtolower((string) $this->_lava->db->raw(
            'SELECT column_type FROM information_schema.columns
             WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?',
            ['users', 'id']
        )->fetchColumn());
        $tokenUserIdType = strtolower((string) $this->_lava->db->raw(
            'SELECT column_type FROM information_schema.columns
             WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?',
            ['email_verification_tokens', 'user_id']
        )->fetchColumn());

        if (!in_array($userIdType, ['int unsigned', 'bigint unsigned'], true)
            || !in_array($tokenUserIdType, ['int unsigned', 'bigint unsigned'], true)) {
            throw new RuntimeException('The user or email verification token ID type is unsupported; no schema changes were made.');
        }
        if ($userIdType === $tokenUserIdType) {
            return;
        }

        $foreignKey = $this->_lava->db->raw(
            'SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
               AND COLUMN_NAME = ? AND REFERENCED_TABLE_NAME = ? LIMIT 1',
            ['email_verification_tokens', 'user_id', 'users']
        )->fetchColumn();
        if ($foreignKey) {
            throw new RuntimeException('The email verification user_id type differs from users.id and has a foreign key; resolve the constraint before changing the column.');
        }

        $this->_lava->db->raw(
            'ALTER TABLE email_verification_tokens MODIFY user_id ' . $userIdType . ' NOT NULL'
        );
    }

    public function down()
    {
    }
}
