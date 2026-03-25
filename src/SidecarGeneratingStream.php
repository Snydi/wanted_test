<?php

declare(strict_types=1);

namespace Wanted\WhatsAppStreamCrypto;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use LogicException;
use Psr\Http\Message\StreamInterface;

/**
 * PSR-7 stream decorator that wraps an EncryptingStream and accumulates
 * its output so that a sidecar can be produced after the stream is fully read.
 *
 * Usage:
 *
 *   $enc    = new EncryptingStream($source, $keys);
 *   $stream = new SidecarGeneratingStream($enc, $keys->iv, $keys->macKey);
 *
 *   $encryptedData = $stream->getContents();
 *   $sidecar       = $stream->getSidecar();
 */
final class SidecarGeneratingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private StreamInterface $stream;

    private string $accumulated = '';

    public function __construct(
        EncryptingStream $source,
        private readonly string $iv,
        private readonly string $macKey,
    ) {
        $this->stream = $source;
    }

    public function read(int $length): string
    {
        $data                = $this->stream->read($length);
        $this->accumulated  .= $data;

        return $data;
    }

    /**
     * Returns the sidecar after the stream has been fully consumed.
     *
     * @throws LogicException if called before the stream is fully read.
     */
    public function getSidecar(): string
    {
        if (!$this->eof()) {
            throw new LogicException(
                'The stream must be fully read before getSidecar() can be called.',
            );
        }

        return SidecarGenerator::compute($this->accumulated, $this->iv, $this->macKey);
    }
}
