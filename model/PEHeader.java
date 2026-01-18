package malware.model;

// Representa el PE Header d’un executable Windows

public class PEHeader {

    // Atributs
    private long signature;
    private int machine;
    private int numberOfSections;
    private long timestamp;
    private long entryPoint;
    private int optionalMagic;
    private long imageBase;
    private long sizeOfCode;
    private long sizeOfImage;

    // Getters i setters
    public long getSignature() {
        return signature;
    }

    public void setSignature(long signature) {
        this.signature = signature;
    }

    public int getMachine() {
        return machine;
    }

    public void setMachine(int machine) {
        this.machine = machine;
    }

    public int getNumberOfSections() {
        return numberOfSections;
    }

    public void setNumberOfSections(int numberOfSections) {
        this.numberOfSections = numberOfSections;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public long getEntryPoint() {
        return entryPoint;
    }

    public void setEntryPoint(long entryPoint) {
        this.entryPoint = entryPoint;
    }

    public int getOptionalMagic() {
        return optionalMagic;
    }

    public void setOptionalMagic(int optionalMagic) {
        this.optionalMagic = optionalMagic;
    }

    public long getImageBase() {
        return imageBase;
    }

    public void setImageBase(long imageBase) {
        this.imageBase = imageBase;
    }

    public long getSizeOfCode() {
        return sizeOfCode;
    }

    public void setSizeOfCode(long sizeOfCode) {
        this.sizeOfCode = sizeOfCode;
    }

    public long getSizeOfImage() {
        return sizeOfImage;
    }

    public void setSizeOfImage(long sizeOfImage) {
        this.sizeOfImage = sizeOfImage;
    }

    // Validació
    public boolean isValid() {
        return signature == 0x00004550L;
    }

    // Informació general del PE
    public String getArchitecture() {
        return switch (machine) {
            case 0x14C -> "x86 (32-bit)";
            case 0x8664 -> "x64 (64-bit)";
            case 0x1C0 -> "ARM";
            case 0xAA64 -> "ARM64";
            default -> "Unknown";
        };
    }

    public boolean is64Bit() {
        return optionalMagic == 0x20B;
    }

    public String getType() {
        return is64Bit() ? "PE32+ (64-bit)" : "PE32 (32-bit)";
    }
}
