package malware.model;

// Serveix per guardar i representar la informació d’una string concreta trobada dins del fitxer

public class StringEntry {

    // Atributs
    private long offset;
    private String value;
    private String type;

    // Constructor
    public StringEntry(long offset, String value, String type) {
        this.offset = offset;
        this.value = value;
        this.type = type;
    }

    // Getters
    public long getOffset() {
         return offset; 
    }

    public String getValue() {
         return value; 
    }

    public String getType() {
         return type; 
    }

    // Format en hexadecimal
    public String getOffsetHex() {
        return String.format("0x%08X", offset);
    }

    // Output en text
    @Override
    public String toString() {
        return String.format("[%s] %s: %s", getOffsetHex(), type, value);
    }
}