<?php

declare(strict_types=1);

namespace Wanted\WhatsAppStreamCrypto;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
use Wanted\WhatsAppStreamCrypto\Exception\CryptoException;

/**
 * PSR-7 stream decorator that encrypts the underlying stream
 * using the WhatsApp media encryption scheme:
 * result = AES-256-CBC(plaintext, cipherKey, iv) + HMAC-SHA256(iv + enc)[0:10]
 * The MAC is appended automatically when the source stream is exhausted.
 */
final class EncryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private const BLOCK_SIZE = 16;
    private const MAC_LENGTH = 10;
    /** Must be a multiple of BLOCK_SIZE to allow chunk-by-chunk CBC encryption. */
    private const CHUNK_SIZE = 8192;

    private StreamInterface $stream;

    private string $buffer          = '';
    private string $plaintextBuffer = '';

    /** Tracks the last ciphertext block to use as IV for the next CBC call. */
    private string $cipherIv;

    /** @var \HashContext */
    private $hmacContext;

    private bool $sourceEof = false;
    private bool $finalized = false;
    private int  $position  = 0;

    public function __construct(StreamInterface $source, private readonly MediaKeyExpanded $keys)
    {
        $this->stream      = $source;
        $this->cipherIv    = $keys->iv;
        $this->hmacContext = hash_init('sha256', HASH_HMAC, $keys->macKey);

        hash_update($this->hmacContext, $keys->iv);
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
     * Returns the exact size of the encrypted output when the source size is known.
     *
     * PKCS7 always adds 1–16 bytes, so:
     *   encryptedSize = sourceSize + BLOCK_SIZE - (sourceSize % BLOCK_SIZE) + MAC_LENGTH
     */
    public function getSize(): ?int
    {
        $sourceSize = $this->stream->getSize();

        if ($sourceSize === null) {
            return null;
        }

        $paddedSize = $sourceSize + self::BLOCK_SIZE - ($sourceSize % self::BLOCK_SIZE);

        return $paddedSize + self::MAC_LENGTH;
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        return $this->finalized && $this->buffer === '';
    }

    public function read(int $length): string
    {
        while (strlen($this->buffer) < $length && !$this->finalized) {
            $this->processNextChunk();
        }

        $result       = substr($this->buffer, 0, $length);
        $this->buffer = substr($this->buffer, $length);
        $this->position += strlen($result);

        return $result;
    }

    private function processNextChunk(): void
    {
        if (!$this->sourceEof) {
            $plain = $this->stream->read(self::CHUNK_SIZE);
            $this->plaintextBuffer .= $plain;

            if ($plain === '' || $this->stream->eof()) {
                $this->sourceEof = true;
            }
        }

        if ($this->sourceEof) {
            $this->finalize();
            return;
        }

        $completeLen = intdiv(strlen($this->plaintextBuffer), self::BLOCK_SIZE) * self::BLOCK_SIZE;
        if ($completeLen === 0) {
            return;
        }

        $plain                 = substr($this->plaintextBuffer, 0, $completeLen);
        $this->plaintextBuffer = substr($this->plaintextBuffer, $completeLen);

        $enc = $this->encryptRawBlock($plain);
        hash_update($this->hmacContext, $enc);
        $this->buffer .= $enc;
    }

    private function finalize(): void
    {
        $padded                = $this->pkcs7Pad($this->plaintextBuffer);
        $this->plaintextBuffer = '';

        $enc = $this->encryptRawBlock($padded);
        hash_update($this->hmacContext, $enc);

        $mac = substr(hash_final($this->hmacContext, true), 0, self::MAC_LENGTH);

        $this->buffer   .= $enc . $mac;
        $this->finalized = true;
    }

    /**
     * OPENSSL_ZERO_PADDING disables OpenSSL's own padding so we control it via pkcs7Pad().
     *
     * @throws CryptoException
     */
    private function encryptRawBlock(string $data): string
    {
        $enc = openssl_encrypt(
            $data,
            'aes-256-cbc',
            $this->keys->cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $this->cipherIv,
        );

        if ($enc === false) {
            throw new CryptoException('OpenSSL encryption failed: ' . openssl_error_string());
        }

        // The last ciphertext block becomes the IV for the next encrypt call.
        $this->cipherIv = substr($enc, -self::BLOCK_SIZE);

        return $enc;
    }

    private function pkcs7Pad(string $data): string
    {
        $pad = self::BLOCK_SIZE - (strlen($data) % self::BLOCK_SIZE);

        return $data . str_repeat(chr($pad), $pad);
    }
}
