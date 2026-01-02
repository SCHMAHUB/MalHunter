package util;

// Calcular Entropía de Shannon de un array de bytes
// Uso de IA para saber como hacer el calculo de la entropia sobre un array de bytes.
public class EntropyCalculator {
    public static double calculate(byte[] data){
        if(data == null || data.length == 0){
            return 0.0;
        }
        // Frequencia de cada valor de byte (0-255)
        int[] frequency = new int[256];
        for (byte b : data) {
            frequency[b & 0xFF]++;
        }
        double entropy = 0.0;
        int dataLength = data.length;

        for (int count : frequency) {
            if (count == 0){
                continue;
            }

            double probability = (double) count / dataLength; // Al ser count y data lenght ints la division sera entre ints y la tenemos que convertir nosotros a double.
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }

        return entropy;
    }

    public static boolean isCompressedOrEncrypted(double entropy) {
        return entropy > 7.0; // El umbral tipico para saber si un archivo esta comprimido o cifrado es una entropia mayor a 7 bits por byte.
    }

    public static String getEntropyLevel(double entropy) {
        // La entropia se mide en bits por byte por tanto se va a encontrar entre 0 y 8 siempre logicamente.
        // Un valor de la entropia se puede decir que es normal siempre que este entre 3 y 7 bits por byte.
        if (entropy < 3.0) {
            return "Very Low";
        } else if (entropy < 5.0) {
            return "Low";
        } else if (entropy < 6.0) {
            return "Medium";
        } else if (entropy < 7.0) {
            return "High";
        } else {
            return "Very High (Suspicious)";
        }
    }
}
