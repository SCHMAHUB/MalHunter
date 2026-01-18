package malware.model;

// Guarda informació sobre una secció del PE (.text, .data...)

public class Section {

    // Atributs
    private String name;
    private long virtualSize;
    private long virtualAddress;
    private long rawSize;
    private long rawPointer;
    private long characteristics;
    private double entropy;
    private byte[] data;
    private double compressionRatio;

    // Constructor
    public Section(String name) {
        this.name = name;
    }

    // Getters i Setters
    public String getName() {
         return name; 
        }
    public void setName(String name) {
         this.name = name; 
        }

    public long getVirtualSize() {
         return virtualSize; 
        }
    public void setVirtualSize(long virtualSize) {
         this.virtualSize = virtualSize; 
        }

    public long getVirtualAddress() {
         return virtualAddress; 
        }
    public void setVirtualAddress(long virtualAddress) {
         this.virtualAddress = virtualAddress; 
        }

    public long getRawSize() {
         return rawSize; 
        }
    public void setRawSize(long rawSize) {
         this.rawSize = rawSize; 
        }

    public long getRawPointer() {
         return rawPointer; 
        }
    public void setRawPointer(long rawPointer) {
         this.rawPointer = rawPointer; 
        }

    public long getCharacteristics() {
         return characteristics; 
        }
    public void setCharacteristics(long characteristics) {
         this.characteristics = characteristics; 
        }

    public double getEntropy() {
         return entropy; 
        }
    public void setEntropy(double entropy) {
         this.entropy = entropy; 
        }

    public byte[] getData() {
         return data; 
        }
    public void setData(byte[] data) {
         this.data = data; 
        }

    public double getCompressionRatio() { 
        return compressionRatio; 
    }
    public void setCompressionRatio(double compressionRatio) { 
        this.compressionRatio = compressionRatio; 
    }

    // Descripció de característiques
    public String getCharacteristicsDescription() {
        StringBuilder sb = new StringBuilder();
        if ((characteristics & 0x20) != 0) sb.append("CODE ");
        if ((characteristics & 0x40) != 0) sb.append("INIT_DATA ");
        if ((characteristics & 0x80) != 0) sb.append("UNINIT_DATA ");
        if ((characteristics & 0x20000000) != 0) sb.append("EXEC ");
        if ((characteristics & 0x40000000) != 0) sb.append("READ ");
        if ((characteristics & 0x80000000L) != 0) sb.append("WRITE ");
        return sb.toString().trim();
    }

    // Comprovació de sospita segons la entropia
    public boolean isSuspicious() {
        if (entropy > 7.0) return true;

        boolean isExecutable = (characteristics & 0x20000000) != 0;
        boolean isWritable = (characteristics & 0x80000000L) != 0;
        if (isExecutable && isWritable) return true;

        if (compressionRatio < 20.0) return true;

        return false;
    }

    // Color segons entropia
    public String getEntropyColor() {
        if (entropy < 3.0) return "#0000FF";
        if (entropy < 5.0) return "#00FF00";
        if (entropy < 7.0) return "#FFA500";
        return "#FF0000";
    }

    // Formats passats a hexadecimal
    public String getVirtualSizeHex() {
        return String.format("0x%08X", virtualSize);
    }

    public String getVirtualAddressHex() {
        return String.format("0x%08X", virtualAddress);
    }

    public String getRawSizeHex() {
        return String.format("0x%08X", rawSize);
    }
}
