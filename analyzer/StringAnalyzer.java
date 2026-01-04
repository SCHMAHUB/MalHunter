package analyzer;

import java.io.*;
import java.nio.charset.StandardCharsets;

public class StringAnalyzer {
    private static final int MIN_STRING_LENGTH = 4;

    // Metodo para analizar los strings en un archivo binario
    public static void analyze()throws IOException{}

    // Faltan las funciones para extraer los strings en ASCII y Unicode para poder completar el metodo analyze
    // Para ello se necesita la peinfo de (PEInfo.java) para obtener la seccion .rdata del archivo PE que aun no esta termianada

    // Metodo para verificar si un byte es un caracter ASCII imprimible
    private static boolean isPrintableASCII(byte b) {
        int value = b & 0xFF;
        return (value >= 32 && value <= 126) || value == 9 || value == 10 || value == 13; // Espacio, tabulacion, nueva linea, retorno de carro
    }

    // Metodo para verificar si un byte es un caracter Unicode imprimible
    private static byte[] readFileBytes(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return fis.readAllBytes();
        }
    }
}
