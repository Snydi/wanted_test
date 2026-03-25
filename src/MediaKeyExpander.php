<?php

declare(strict_types=1);

namespace Wanted\WhatsAppStreamCrypto;

use Wanted\WhatsAppStreamCrypto\Enum\MediaType;
use Wanted\WhatsAppStreamCrypto\Exception\CryptoException;

final class MediaKeyExpander
{
    private const MEDIA_KEY_LENGTH = 32;
    private const EXPANDED_LENGTH  = 112;

    /**
     * Expands a 32-byte mediaKey to 112 bytes using HKDF with SHA-256.
     * @throws CryptoException if the key has wrong length
     */
    public static function expand(string $mediaKey, MediaType $type): MediaKeyExpanded
    {
        if (strlen($mediaKey) !== self::MEDIA_KEY_LENGTH) {
            throw new CryptoException(sprintf(
                'mediaKey must be exactly %d bytes, got %d.',
                self::MEDIA_KEY_LENGTH,
                strlen($mediaKey),
            ));
        }

        $expanded = hash_hkdf('sha256', $mediaKey, self::EXPANDED_LENGTH, $type->value);

        return new MediaKeyExpanded(
            iv:        substr($expanded, 0, 16),
            cipherKey: substr($expanded, 16, 32),
            macKey:    substr($expanded, 48, 32),
        );
    }
}
