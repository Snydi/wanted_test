<?php

declare(strict_types=1);

namespace Wanted\WhatsAppStreamCrypto\Tests;

use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Wanted\WhatsAppStreamCrypto\DecryptingStream;
use Wanted\WhatsAppStreamCrypto\EncryptingStream;
use Wanted\WhatsAppStreamCrypto\Enum\MediaType;
use Wanted\WhatsAppStreamCrypto\MediaKeyExpander;

final class EncryptingStreamTest extends TestCase
{
    public static function sampleFilesProvider(): array
    {
        return [
            'image' => [MediaType::IMAGE, 'IMAGE'],
            'audio' => [MediaType::AUDIO, 'AUDIO'],
            'video' => [MediaType::VIDEO, 'VIDEO'],
        ];
    }

    #[DataProvider('sampleFilesProvider')]
    public function testEncryptsToExpectedOutput(MediaType $type, string $prefix): void
    {
        $mediaKey  = $this->readSample($prefix . '.key');
        $original  = $this->readSample($prefix . '.original');
        $expected  = $this->readSample($prefix . '.encrypted');

        $keys   = MediaKeyExpander::expand($mediaKey, $type);
        $source = Utils::streamFor($original);
        $stream = new EncryptingStream($source, $keys);

        $this->assertSame($expected, $stream->getContents());
    }

    #[DataProvider('sampleFilesProvider')]
    public function testGetSizeMatchesActualOutput(MediaType $type, string $prefix): void
    {
        $mediaKey = $this->readSample($prefix . '.key');
        $original = $this->readSample($prefix . '.original');

        $keys   = MediaKeyExpander::expand($mediaKey, $type);
        $source = Utils::streamFor($original);
        $stream = new EncryptingStream($source, $keys);

        $declaredSize = $stream->getSize();
        $actualSize   = strlen($stream->getContents());

        $this->assertSame($actualSize, $declaredSize);
    }

    #[DataProvider('sampleFilesProvider')]
    public function testPositionAndEof(MediaType $type, string $prefix): void
    {
        $mediaKey = $this->readSample($prefix . '.key');
        $original = $this->readSample($prefix . '.original');

        $keys   = MediaKeyExpander::expand($mediaKey, $type);
        $source = Utils::streamFor($original);
        $stream = new EncryptingStream($source, $keys);

        $this->assertSame(0, $stream->tell());
        $this->assertFalse($stream->eof());

        $result = $stream->getContents();

        $this->assertSame(strlen($result), $stream->tell());
        $this->assertTrue($stream->eof());
    }

    #[DataProvider('sampleFilesProvider')]
    public function testRoundTrip(MediaType $type, string $prefix): void
    {
        $mediaKey = $this->readSample($prefix . '.key');
        $original = $this->readSample($prefix . '.original');

        $keys = MediaKeyExpander::expand($mediaKey, $type);

        $encryptedStream = new EncryptingStream(Utils::streamFor($original), $keys);
        $encryptedData   = $encryptedStream->getContents();

        $decryptedStream = new DecryptingStream(
            Utils::streamFor($encryptedData),
            $keys,
        );

        $this->assertSame($original, $decryptedStream->getContents());
    }


    private function readSample(string $filename): string
    {
        $path = dirname(__DIR__) . '/samples/' . $filename;

        $data = file_get_contents($path);

        $this->assertNotFalse($data, "Sample file not found: $path");

        return $data;
    }
}
