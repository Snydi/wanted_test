<?php

declare(strict_types=1);

namespace Wanted\WhatsAppStreamCrypto\Tests;

use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Wanted\WhatsAppStreamCrypto\DecryptingStream;
use Wanted\WhatsAppStreamCrypto\Enum\MediaType;
use Wanted\WhatsAppStreamCrypto\Exception\IntegrityException;
use Wanted\WhatsAppStreamCrypto\MediaKeyExpander;

final class DecryptingStreamTest extends TestCase
{
    public static function sampleFilesProvider(): array
    {
        return [
            'image'    => [MediaType::IMAGE, 'IMAGE'],
            'audio'    => [MediaType::AUDIO, 'AUDIO'],
            'video'    => [MediaType::VIDEO, 'VIDEO'],
        ];
    }

    #[DataProvider('sampleFilesProvider')]
    public function testDecryptsToOriginal(MediaType $type, string $prefix): void
    {
        $mediaKey  = $this->readSample($prefix . '.key');
        $encrypted = $this->readSample($prefix . '.encrypted');
        $original  = $this->readSample($prefix . '.original');

        $keys   = MediaKeyExpander::expand($mediaKey, $type);
        $source = Utils::streamFor($encrypted);
        $stream = new DecryptingStream($source, $keys);

        $this->assertSame($original, $stream->getContents());
    }

    #[DataProvider('sampleFilesProvider')]
    public function testThrowsOnTamperedData(MediaType $type, string $prefix): void
    {
        $mediaKey  = $this->readSample($prefix . '.key');
        $encrypted = $this->readSample($prefix . '.encrypted');

        // Меняем один байт в середине зашифрованных данных.
        $pos = (int)(strlen($encrypted) / 2);
        $encrypted[$pos] = chr((ord($encrypted[$pos]) + 1) % 256);

        $keys   = MediaKeyExpander::expand($mediaKey, $type);
        $source = Utils::streamFor($encrypted);
        $stream = new DecryptingStream($source, $keys);

        $this->expectException(IntegrityException::class);
        $stream->getContents();
    }

    #[DataProvider('sampleFilesProvider')]
    public function testPositionAndEof(MediaType $type, string $prefix): void
    {
        $mediaKey  = $this->readSample($prefix . '.key');
        $encrypted = $this->readSample($prefix . '.encrypted');

        $keys   = MediaKeyExpander::expand($mediaKey, $type);
        $source = Utils::streamFor($encrypted);
        $stream = new DecryptingStream($source, $keys);

        $this->assertSame(0, $stream->tell());
        $this->assertFalse($stream->eof());

        $stream->getContents();

        $this->assertTrue($stream->eof());
    }

    private function readSample(string $filename): string
    {
        $path = dirname(__DIR__) . '/samples/' . $filename;

        $data = file_get_contents($path);

        $this->assertNotFalse($data, "Sample file not found: $path");

        return $data;
    }
}
