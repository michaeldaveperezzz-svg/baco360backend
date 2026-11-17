<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

use Aws\Exception\AwsException;
use Aws\S3\S3Client;

class ReportAttachmentNotFoundException extends RuntimeException
{
}

class ReportAttachmentStorage
{
    private $driver;
    private $directory;
    private $bucket;
    private $s3Client;

    public function __construct(array $config)
    {
        $accountId = trim((string) ($config['account_id'] ?? ''));
        $bucket = trim((string) ($config['bucket'] ?? ''));
        $accessKeyId = trim((string) ($config['access_key_id'] ?? ''));
        $secretAccessKey = trim((string) ($config['secret_access_key'] ?? ''));
        $configuredR2Values = array_filter(
            [$accountId, $bucket, $accessKeyId, $secretAccessKey],
            static function ($value) {
                return $value !== '';
            }
        );

        if (count($configuredR2Values) === 4) {
            if (preg_match('/\A[a-f0-9]{32}\z/i', $accountId) !== 1) {
                throw new RuntimeException('The Cloudflare R2 account ID is invalid.');
            }
            $this->driver = 'r2';
            $this->bucket = $bucket;
            $this->s3Client = new S3Client([
                'version' => 'latest',
                'region' => 'auto',
                'endpoint' => 'https://' . $accountId . '.r2.cloudflarestorage.com',
                'use_path_style_endpoint' => true,
                'signature_version' => 'v4',
                'credentials' => [
                    'key' => $accessKeyId,
                    'secret' => $secretAccessKey,
                ],
            ]);
            return;
        }

        if (count($configuredR2Values) > 0) {
            throw new RuntimeException('Cloudflare R2 configuration is incomplete.');
        }
        if (strtolower(trim((string) ($config['app_env'] ?? ''))) !== 'development') {
            throw new RuntimeException('Cloudflare R2 storage must be configured outside development.');
        }

        $directory = trim((string) ($config['local_directory'] ?? ''));
        if ($directory === '') {
            $directory = (string) ($config['default_local_directory'] ?? '');
        }
        if ($directory === '') {
            throw new RuntimeException('Local report attachment storage is not configured.');
        }

        $this->driver = 'local';
        $this->directory = rtrim($directory, "/\\") . DIRECTORY_SEPARATOR;
    }

    public function storeUploadedFile($temporaryPath, $key, $mimeType)
    {
        $this->validateKey($key);

        if ($this->driver === 'local') {
            $this->ensureLocalDirectory();
            if (!move_uploaded_file($temporaryPath, $this->directory . $key)) {
                throw new RuntimeException('The uploaded report attachment could not be saved.');
            }
            return;
        }

        $body = fopen($temporaryPath, 'rb');
        if ($body === false) {
            throw new RuntimeException('The uploaded report attachment could not be read.');
        }

        try {
            $this->s3Client->putObject([
                'Bucket' => $this->bucket,
                'Key' => $key,
                'Body' => $body,
                'ContentType' => $mimeType,
            ]);
        } catch (AwsException $error) {
            throw new RuntimeException(
                'Cloudflare R2 upload failed: ' . ($error->getAwsErrorMessage() ?: $error->getMessage()),
                0,
                $error
            );
        } finally {
            fclose($body);
        }
    }

    public function get($key)
    {
        $this->validateKey($key);

        if ($this->driver === 'local') {
            $directory = realpath($this->directory);
            if ($directory === false) {
                throw new ReportAttachmentNotFoundException('Report attachment not found.');
            }
            $path = realpath($directory . DIRECTORY_SEPARATOR . $key);
            if ($path === false || dirname($path) !== $directory || !is_file($path)) {
                throw new ReportAttachmentNotFoundException('Report attachment not found.');
            }
            $body = fopen($path, 'rb');
            if ($body === false) {
                throw new RuntimeException('The report attachment could not be read.');
            }
            return [
                'body' => $body,
                'content_length' => filesize($path),
            ];
        }

        try {
            $object = $this->s3Client->getObject([
                'Bucket' => $this->bucket,
                'Key' => $key,
            ]);
        } catch (AwsException $error) {
            if (
                (int) $error->getStatusCode() === 404
                || in_array($error->getAwsErrorCode(), ['NoSuchKey', 'NotFound'], true)
            ) {
                throw new ReportAttachmentNotFoundException('Report attachment not found.', 0, $error);
            }
            throw new RuntimeException(
                'Cloudflare R2 download failed: ' . ($error->getAwsErrorMessage() ?: $error->getMessage()),
                0,
                $error
            );
        }

        return [
            'body' => $object['Body'],
            'content_length' => (int) $object['ContentLength'],
        ];
    }

    public function delete($key)
    {
        $this->validateKey($key);

        if ($this->driver === 'local') {
            $directory = realpath($this->directory);
            if ($directory === false) {
                return true;
            }
            $path = realpath($directory . DIRECTORY_SEPARATOR . $key);
            if ($path === false) {
                return true;
            }
            if (dirname($path) !== $directory || !unlink($path)) {
                return false;
            }
            return true;
        }

        try {
            $this->s3Client->deleteObject([
                'Bucket' => $this->bucket,
                'Key' => $key,
            ]);
            return true;
        } catch (AwsException $error) {
            throw new RuntimeException(
                'Cloudflare R2 deletion failed: ' . ($error->getAwsErrorMessage() ?: $error->getMessage()),
                0,
                $error
            );
        }
    }

    private function ensureLocalDirectory()
    {
        if (!is_dir($this->directory)
            && !mkdir($this->directory, 0750, true)
            && !is_dir($this->directory)) {
            throw new RuntimeException('Local report attachment storage is unavailable.');
        }
        if (!is_writable($this->directory)) {
            throw new RuntimeException('Local report attachment storage is not writable.');
        }
    }

    private function validateKey($key)
    {
        if (
            !is_string($key)
            || $key === ''
            || $key === '.'
            || $key === '..'
            || strpos($key, '/') !== false
            || strpos($key, '\\') !== false
        ) {
            throw new InvalidArgumentException('Invalid report attachment key.');
        }
    }
}
