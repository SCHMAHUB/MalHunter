package malware.model; 

// Un DOS Header = MZ Header, que es per saber si un programa conté signatura MZ, que es compatible amb windows

public class DOSHeader {

    private int magic;          

    private long peOffset;      

    public DOSHeader(int magic, long peOffset) { // Constructor de la classe DOSHeader, inicialitza els camps
        this.magic = magic;        // Assigna el valor màgic llegit (el MZ)
        this.peOffset = peOffset;  // Assigna l’offset del PE Header (posició en bytes)
    }

    public int getMagic() {
        return magic;
    } // Return del valor "màgic" del DOS Header

    public long getPeOffset() {
        return peOffset; // Return del offset al PE Header
    }
    
    public boolean isValid() { // Comprova si el DOS Header és vàlid, és vàlid si el valor màgic coincideix amb "MZ"
        return magic == 0x5A4D; // 0x5A4D és el valor hexadecimal que representa "MZ" en ASCII
    }

    public String getMagicHex() { // Retorna el valor màgic en format hexadecimal
        return String.format("0x%04X", magic); // %04X indica que es mostrarà el valor en hexadecimal amb 4 digits
    }

    public String getPeOffsetHex() { // Retorna l’offset del PE Header en format hexadecimal.
        return String.format("0x%08X", peOffset);// %08X indica que es mostrarà el valor en hexadecimal amb 8 digits
    }
}