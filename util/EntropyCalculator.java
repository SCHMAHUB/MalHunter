package util;

// Calculate the Shannon Entropy of a byte array
public class EntropyCalculator {
    public static double calculate(byte[] data){
        if(data == null || data.length == 0){
            return 0.0;
        }
        // Frequency of each byte value (0-255)
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

            double probability = (double) count / dataLength;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }

        return entropy;
    }

    public static boolean isCompressedOrEncrypted(double entropy) {
        return entropy > 7.0;
    }

    public static String getEntropyLevel(double entropy) {
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
