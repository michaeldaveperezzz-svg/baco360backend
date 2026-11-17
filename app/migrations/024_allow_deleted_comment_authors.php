<?php

class Allow_deleted_comment_authors
{
    private $_lava;

    public function __construct()
    {
        $this->_lava = lava_instance();
        $this->_lava->call->dbforge();
    }

    public function up()
    {
        foreach (['report_comments', 'community_report_comments'] as $table) {
            $columnType = $this->_lava->db->raw(
                'SELECT COLUMN_TYPE FROM information_schema.columns
                 WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?',
                [$table, 'user_id']
            )->fetchColumn();
            if (!is_string($columnType)
                || preg_match('/\A(?:int|bigint)(?:\(\d+\))?(?: unsigned)?\z/i', $columnType) !== 1) {
                throw new RuntimeException('The ' . $table . '.user_id column is missing or has an unsupported type; no changes were made.');
            }

            $this->_lava->db->raw(
                'ALTER TABLE `' . $table . '` MODIFY COLUMN `user_id` ' . $columnType . ' NULL'
            );
        }
    }

    public function down()
    {
    }
}
