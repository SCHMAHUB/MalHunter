package malware.model; 

// Un DOS Header = MZ Header, que es per saber si un programa conté signatura MZ, que es compatible amb windows

public class DOSHeader {

    // Atributs
    private int magic;          
    private long peOffset;      

    // Constructor
    public DOSHeader(int magic, long peOffset) { 
        this.magic = magic;
        this.peOffset = peOffset;
    }
    
    // Getters
    public int getMagic() {
        return magic;
    }

    public long getPeOffset() {
        return peOffset;
    }

    // Validació amb MZ
    public boolean isValid() {
        return magic == 0x5A4D;
    }

    // Formats en hexadecimal
    public String getMagicHex() {
        return String.format("0x%04X", magic);
    }

    public String getPeOffsetHex() {
        return String.format("0x%08X", peOffset);
    }
}
