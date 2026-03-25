<?php

declare(strict_types=1);

namespace Wanted\WhatsAppStreamCrypto\Tests;

use GuzzleHttp\Psr7\Utils;
use LogicException;
use PHPUnit\Framework\TestCase;
use Wanted\WhatsAppStreamCrypto\EncryptingStream;
use Wanted\WhatsAppStreamCrypto\Enum\MediaType;
use Wanted\WhatsAppStreamCrypto\MediaKeyExpander;
use Wanted\WhatsAppStreamCrypto\SidecarGeneratingStream;

final class SidecarGeneratingStreamTest extends TestCase
{
    public function testGeneratesSidecarMatchingSample(): void
    {
        $mediaKey        = $this->readSample('VIDEO.key');
        $original        = $this->readSample('VIDEO.original');
        $expectedSidecar = $this->readSample('VIDEO.sidecar');

        $keys            = MediaKeyExpander::expand($mediaKey, MediaType::VIDEO);
        $encryptingStream = new EncryptingStream(Utils::streamFor($original), $keys);
        $sidecarStream   = new SidecarGeneratingStream($encryptingStream, $keys->iv, $keys->macKey);

        // Читаем поток — это одновременно шифрует данные И накапливает байты
        // для будущего вычисления sidecar. Второго прохода по plaintext нет.
        $sidecarStream->getContents();

        $this->assertSame($expectedSidecar, $sidecarStream->getSidecar());
    }

    public function testEncryptedOutputIsUnchanged(): void
    {
        $mediaKey = $this->readSample('VIDEO.key');
        $original = $this->readSample('VIDEO.original');
        $expected = $this->readSample('VIDEO.encrypted');

        $keys = MediaKeyExpander::expand($mediaKey, MediaType::VIDEO);

        $sidecarStream = new SidecarGeneratingStream(
            new EncryptingStream(Utils::streamFor($original), $keys),
            $keys->iv,
            $keys->macKey,
        );

        $this->assertSame($expected, $sidecarStream->getContents());
    }

    public function testThrowsIfStreamNotFullyRead(): void
    {
        $mediaKey = $this->readSample('VIDEO.key');
        $original = $this->readSample('VIDEO.original');
        $keys     = MediaKeyExpander::expand($mediaKey, MediaType::VIDEO);

        $stream = new SidecarGeneratingStream(
            new EncryptingStream(Utils::streamFor($original), $keys),
            $keys->iv,
            $keys->macKey,
        );

        $this->expectException(LogicException::class);
        $stream->getSidecar();
    }

    private function readSample(string $filename): string
    {
        $path = dirname(__DIR__) . '/samples/' . $filename;
        $data = file_get_contents($path);
        $this->assertNotFalse($data, "Sample file not found: $path");

        return $data;
    }
}
