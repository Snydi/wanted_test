<?php

declare(strict_types=1);

namespace Wanted\WhatsAppStreamCrypto;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
use Wanted\WhatsAppStreamCrypto\Exception\CryptoException;
use Wanted\WhatsAppStreamCrypto\Exception\IntegrityException;

/**
 * PSR-7 stream decorator that decrypts a WhatsApp-encrypted stream.
 * Encrypted format expected:
 *   [ AES-256-CBC ciphertext (PKCS7-padded) ][ HMAC-SHA256 truncated to 10 bytes ]
 * The entire source is consumed on the first read so the MAC can be verified
 * before any plaintext is returned to the caller.
 */
final class DecryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private const MAC_LENGTH = 10;

    private StreamInterface $stream;

    private ?string $plaintextBuffer = null;
    private int     $position        = 0;

    public function __construct(StreamInterface $source, private readonly MediaKeyExpanded $keys)
    {
        $this->stream = $source;
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function isSeekable(): bool
    {
        return false;
    }

    /**
     * Plaintext size cannot be determined without decrypting (PKCS7 padding varies).
     */
    public function getSize(): ?int
    {
        return null;
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        if ($this->plaintextBuffer === null) {
            return false;
        }

        return $this->plaintextBuffer === '';
    }

    public function read(int $length): string
    {
        if ($this->plaintextBuffer === null) {
            $this->loadAndVerify();
        }

        $result                = substr($this->plaintextBuffer, 0, $length);
        $this->plaintextBuffer = substr($this->plaintextBuffer, $length);
        $this->position        += strlen($result);

        return $result;
    }

    /**
     * @throws IntegrityException if the MAC does not match
     * @throws CryptoException    on OpenSSL failure or malformed input
     */
    private function loadAndVerify(): void
    {
        $encrypted = $this->stream->getContents();

        if (strlen($encrypted) < self::MAC_LENGTH) {
            throw new CryptoException(sprintf(
                'Encrypted data is too short: expected at least %d bytes, got %d.',
                self::MAC_LENGTH,
                strlen($encrypted),
            ));
        }

        $ciphertext = substr($encrypted, 0, -self::MAC_LENGTH);
        $mac        = substr($encrypted, -self::MAC_LENGTH);

        $this->verifyMac($ciphertext, $mac);

        $this->plaintextBuffer = $this->decrypt($ciphertext);
    }

    /** @throws IntegrityException */
    private function verifyMac(string $ciphertext, string $mac): void
    {
        $expected = substr(
            hash_hmac('sha256', $this->keys->iv . $ciphertext, $this->keys->macKey, true),
            0,
            self::MAC_LENGTH,
        );

        if (!hash_equals($expected, $mac)) {
            throw new IntegrityException(
                'MAC verification failed: the encrypted data may be corrupted or tampered with.',
            );
        }
    }

    /** @throws CryptoException */
    private function decrypt(string $ciphertext): string
    {
        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-cbc',
            $this->keys->cipherKey,
            OPENSSL_RAW_DATA,
            $this->keys->iv,
        );

        if ($plaintext === false) {
            throw new CryptoException('OpenSSL decryption failed: ' . openssl_error_string());
        }

        return $plaintext;
    }
}
