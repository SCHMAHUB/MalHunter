package util;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;

public class BinaryReader {
    // Leer INTs de 16, 32 o 64 bits
    // Uso de IA para implementar lectura de enteros sin signo desde binario (little-endian),
    // aplicando máscara (& 0xFF) para tratar bytes como 0–255 y luego recomponer usando desplazamientos.
    public static int readUInt16(RandomAccessFile raf) throws IOException {
        // Uso de la clase RandomAccessFile para leer bytes individuales.
        // La máscara & 0xFF conserva únicamente los 8 bits del byte y pone a 0 los bits superiores del int (porque los ints son de 32 bits y queremos de 8 bits),
        // esto lo hacemos para evitar la extensión de signo.
        int b1 = raf.read() & 0xFF;
        int b2 = raf.read() & 0xFF;
        return b1 | (b2 << 8); // Desplazamiento de 8 bits sobre el segundo byte para que no colisione con el primer byte.
    }

    public static long readUInt32(RandomAccessFile raf) throws IOException {
        long b1 = raf.read() & 0xFF;
        long b2 = raf.read() & 0xFF;
        long b3 = raf.read() & 0xFF;
        long b4 = raf.read() & 0xFF;
        // Los desplazamientos funcionan igual que en la función anterior pero cada byte son 8 bits mas desplazados (usamos << para desplazar).
        return b1 | (b2 << 8) | (b3 << 16) | (b4 << 24); 
    }

    public static long readUInt64(RandomAccessFile raf) throws IOException {
        // 0xFFL es la misma máscara que en 0xFF (0–255) pero en long; así toda la recomposición se hace en 64 bits.
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

    // Leer una cadena de un tamaño fijo
    public static String readFixedString(RandomAccessFile raf, int length) throws IOException {
        byte[] buffer = new byte[length];
        raf.read(buffer);

        // Encontrar la posición del primer byte nulo
        int nullPos = 0;
        for (int i = 0; i < buffer.length; i++) {
            if (buffer[i] == 0) {
                nullPos = i;
                break;
            }
        }
        if (nullPos == 0) nullPos = buffer.length;

        // Decodifica los bytes del buffer [0..nullPos) en UTF-8 (sin depender del charset del sistema usando StandardCharsets.UTF_8) y limpia espacios con trim().
        return new String(buffer, 0, nullPos, StandardCharsets.UTF_8).trim();
    }

    public static byte[] readBytes(RandomAccessFile raf, int length) throws IOException {
        byte[] buffer = new byte[length];
        raf.readFully(buffer);
        return buffer;
    }
}
