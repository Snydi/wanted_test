<?php

declare(strict_types=1);

namespace Wanted\WhatsAppStreamCrypto\Exception;

use RuntimeException;

/**
 * Thrown when the HMAC-SHA256 MAC verification fails during decryption,
 * indicating that the encrypted data has been tampered with or corrupted.
 */
final class IntegrityException extends RuntimeException {}
