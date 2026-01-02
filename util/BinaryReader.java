package util;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;

public class BinaryReader {
    // Read a INT of 16, 32 or 64 bits
    public static int readUInt16(RandomAccessFile raf) throws IOException {
        int b1 = raf.read() & 0xFF;
        int b2 = raf.read() & 0xFF;
        return b1 | (b2 << 8);
    }

    public static long readUInt32(RandomAccessFile raf) throws IOException {
        long b1 = raf.read() & 0xFF;
        long b2 = raf.read() & 0xFF;
        long b3 = raf.read() & 0xFF;
        long b4 = raf.read() & 0xFF;
        return b1 | (b2 << 8) | (b3 << 16) | (b4 << 24);
    }

    public static long readUInt64(RandomAccessFile raf) throws IOException {
        long b1 = raf.read() & 0xFFL;
        long b2 = raf.read() & 0xFFL;
        long b3 = raf.read() & 0xFFL;
        long b4 = raf.read() & 0xFFL;
        long b5 = raf.read() & 0xFFL;
        long b6 = raf.read() & 0xFFL;
        long b7 = raf.read() & 0xFFL;
        long b8 = raf.read() & 0xFFL;
        return b1 | (b2 << 8) | (b3 << 16) | (b4 << 24) | (b5 << 32) | (b6 << 40) | (b7 << 48) | (b8 << 56);
    }

    // Read a string of fixed length
    public static String readFixedString(RandomAccessFile raf, int length) throws IOException {
        byte[] buffer = new byte[length];
        raf.read(buffer);

        // Find the NULL value
        int nullPos = 0;
        for (int i = 0; i < buffer.length; i++) {
            if (buffer[i] == 0) {
                nullPos = i;
                break;
            }
        }
        if (nullPos == 0) nullPos = buffer.length;

        return new String(buffer, 0, nullPos, StandardCharsets.UTF_8).trim();
    }

    public static byte[] readBytes(RandomAccessFile raf, int length) throws IOException {
        byte[] buffer = new byte[length];
        raf.readFully(buffer);
        return buffer;
    }
}
