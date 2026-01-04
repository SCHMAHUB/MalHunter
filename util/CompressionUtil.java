package util;

import java.io.ByteArrayOutputStream;
import java.util.zip.Deflater;

public class CompressionUtil {
    public static double calculateCompressionRatio(byte[] data){
        if(data == null || data.length == 0){
            return 0.0; // Verificamos que el array no este vacio o sea nulo antes que nada, en caso de que lo sea retornamos 0
        }

        try {
            // Comprimir los datos usando Deflater, usamos BEST_COMPRESSION para usar la compresión más rápida posible
            Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
            deflater.setInput(data);
            deflater.finish();

            // Creamos un ByteArrayOutputStream para almacenar los datos comprimidos y le asignamos un tamaño inicial igual al del array original
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
            byte[] buffer = new byte[1024]; // Buffer temporal para almacenar los datos comprimidos

            // Mientras no se haya terminado la compresion, seguimos comprimiendo los datos y escribiendolos en el ByteArrayOutputStream
            while (!deflater.finished()) {
                int count = deflater.deflate(buffer);
                outputStream.write(buffer, 0, count);
            }

            // Cerramos el ByteArrayOutputStream y el deflater
            outputStream.close();
            deflater.end();

            byte[] compressedData = outputStream.toByteArray();

            // Calculamos el ratio con la formula: tamaño comprimido / tamaño original
            double ratio = (double) data.length / compressedData.length;

            return ratio;

        }catch (Exception e){
            return 0.0;
        }
    }
}
