<?php

declare(strict_types=1);

namespace Wanted\WhatsAppStreamCrypto;

/**
 * Computes the WhatsApp sidecar for streamable media (video, audio).
 *
 * The sidecar enables random seek in encrypted media: to decrypt a 64 KB chunk
 * at offset n*64K the player needs only that chunk plus its CBC IV (the last
 * AES block of the preceding chunk). Each sidecar entry authenticates exactly
 * that material:
 *
 *   entry[0] = HMAC-SHA256(macKey, originalIv + enc[0..64K))[0:10]
 *   entry[n] = HMAC-SHA256(macKey, enc[n*64K-16..n*64K) + enc[n*64K..(n+1)*64K))[0:10]
 *
 * The last chunk includes the trailing 10-byte global MAC because that is what
 * is physically stored on disk.
 *
 * Accepts the full output of EncryptingStream (ciphertext + 10-byte MAC).
 */
final class SidecarGenerator
{
    private const CHUNK_SIZE    = 65536; // 64 KiB
    private const BLOCK_SIZE    = 16;    // AES block / CBC IV length
    private const GLOBAL_MAC    = 10;    // trailing bytes produced by EncryptingStream
    private const SIDECAR_ENTRY = 10;

    public static function compute(string $fullEncrypted, string $iv, string $macKey): string
    {
        $cipherLen  = strlen($fullEncrypted) - self::GLOBAL_MAC;
        $sidecar    = '';
        $chunkIndex = 0;

        while ($chunkIndex * self::CHUNK_SIZE < $cipherLen) {
            $offset = $chunkIndex * self::CHUNK_SIZE;

            // For chunk 0 the prefix is the original IV; for all others it is
            // the last AES block of the previous chunk (the CBC IV for decryption).
            $prefix = $chunkIndex === 0
                ? $iv
                : substr($fullEncrypted, $offset - self::BLOCK_SIZE, self::BLOCK_SIZE);

            $chunkData = substr($fullEncrypted, $offset, self::CHUNK_SIZE);

            $sidecar .= substr(
                hash_hmac('sha256', $prefix . $chunkData, $macKey, true),
                0,
                self::SIDECAR_ENTRY,
            );

            $chunkIndex++;
        }

        return $sidecar;
    }
}
