package malware.model;

// Representa el PE Header d’un executable Windows

public class PEHeader {

    private long signature;
    private int machine;
    private int numberOfSections;
    private long timestamp;
    private long entryPoint;
    private int optionalMagic;
    private long imageBase;
    private long sizeOfCode;
    private long sizeOfImage;

    public long getSignature() {
        return signature; // Return de la signatura
    }

    public void setSignature(long signature) {
        this.signature = signature; // Assigna la signatura
    }

    public int getMachine() {
        return machine; // Return arquitectura
    }

    public void setMachine(int machine) {
        this.machine = machine; // Assigna arquitectura
    }

    public int getNumberOfSections() {
        return numberOfSections; // Return nombre de seccions
    }

    public void setNumberOfSections(int numberOfSections) {
        this.numberOfSections = numberOfSections; // Assigna seccions
    }

    public long getTimestamp() {
        return timestamp; // Return data de compilació
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp; // Assigna timestamp
    }

    public long getEntryPoint() {
        return entryPoint; // Return punt d’entrada
    }

    public void setEntryPoint(long entryPoint) {
        this.entryPoint = entryPoint; // Assigna punt d’entrada
    }

    public int getOptionalMagic() {
        return optionalMagic; // Return tipus PE
    }

    public void setOptionalMagic(int optionalMagic) {
        this.optionalMagic = optionalMagic; // Assigna tipus PE
    }

    public long getImageBase() {
        return imageBase; // Return image base
    }

    public void setImageBase(long imageBase) {
        this.imageBase = imageBase; // Assigna image base
    }

    public long getSizeOfCode() {
        return sizeOfCode; // Return mida del codi
    }

    public void setSizeOfCode(long sizeOfCode) {
        this.sizeOfCode = sizeOfCode; // Assigna mida del codi
    }

    public long getSizeOfImage() {
        return sizeOfImage; // Return mida de la imatge
    }

    public void setSizeOfImage(long sizeOfImage) {
        this.sizeOfImage = sizeOfImage; // Assigna mida de la imatge
    }

    public boolean isValid() {
        return signature == 0x00004550L; // Comprova si el PE és vàlid
    }

    public String getArchitecture() {
        return switch (machine) { // Detecta l’arquitectura (tipus de CPU per a la qual s’ha compilat el programa)
            case 0x14C -> "x86 (32-bit)";
            case 0x8664 -> "x64 (64-bit)";
            case 0x1C0 -> "ARM";
            case 0xAA64 -> "ARM64";
            default -> "Unknown";
        };
    }

    public boolean is64Bit() {
        return optionalMagic == 0x20B; // Diu si el PE és de 64 bits
    }

    public String getType() {
        return is64Bit() ? "PE32+ (64-bit)" : "PE32 (32-bit)"; // Tipus de PE, comprovant si es de 64 amb el boolean anterior i si no ho és ho marca com a 32-bit
    }
}
