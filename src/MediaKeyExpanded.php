<?php

declare(strict_types=1);

namespace Wanted\WhatsAppStreamCrypto;

/**
 * Key material derived from HKDF expansion of a 32-byte mediaKey.
 *
 * Layout of the 112-byte expanded key:
 *   [  0..15 ] iv        — AES-CBC initialization vector
 *   [ 16..47 ] cipherKey — AES-CBC encryption key
 *   [ 48..79 ] macKey    — HMAC-SHA256 signing key
 *   [ 80..111] refKey    — reserved, not used
 */
final readonly class MediaKeyExpanded
{
    public function __construct(
        public string $iv,        // 16 bytes
        public string $cipherKey, // 32 bytes
        public string $macKey,    // 32 bytes
    ) {}
}
