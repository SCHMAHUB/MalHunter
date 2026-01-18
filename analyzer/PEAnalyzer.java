import model.*;
import util.BinaryReader;
import util.EntropyCalculator;
import util.CompressionUtil;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.*;

/**
 * Analizador de archivos PE
 */
public class PEAnalyzer {

    public static PEInfo analyze(File file) throws IOException {
        PEInfo peInfo = new PEInfo(file);

        calculateHashes(peInfo);

        parseHeaders(peInfo);

        byte[] fileData = readFileBytes(file);
        peInfo.setEntropy(EntropyCalculator.calculate(fileData));

        return peInfo;
    }

    // Metodo para calcular hashes
    private static void calculateHashes(PEInfo peInfo) throws IOException {
        File file = peInfo.getFile();

        try (FileInputStream fis = new FileInputStream(file)) {
            peInfo.setMd5(DigestUtils.md5Hex(fis));
        }
        try (FileInputStream fis = new FileInputStream(file)) {
            peInfo.setSha1(DigestUtils.sha1Hex(fis));
        }
        try (FileInputStream fis = new FileInputStream(file)) {
            peInfo.setSha256(DigestUtils.sha256Hex(fis));
        }
    }

    // Metodo para parsear estructuras PE
    private static void parseHeaders(PEInfo peInfo) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(peInfo.getFile(), "r")) {
            raf.seek(0);
            int magic = BinaryReader.readUInt16(raf);
            raf.seek(0x3C);
            long peOffset = BinaryReader.readUInt32(raf);

            DOSHeader dosHeader = new DOSHeader(magic, peOffset);
            peInfo.setDosHeader(dosHeader);

            if (!dosHeader.isValid()) {
                throw new IOException("Invalid DOS signature");
            }

            raf.seek(peOffset);
            long peSignature = BinaryReader.readUInt32(raf);

            PEHeader peHeader = new PEHeader();
            peHeader.setSignature(peSignature);

            if (!peHeader.isValid()) {
                throw new IOException("Invalid PE signature");
            }

            peHeader.setMachine(BinaryReader.readUInt16(raf));
            peHeader.setNumberOfSections(BinaryReader.readUInt16(raf));
            peHeader.setTimestamp(BinaryReader.readUInt32(raf));
            raf.skipBytes(8); // PointerToSymbolTable + NumberOfSymbols
            int sizeOfOptionalHeader = BinaryReader.readUInt16(raf);
            raf.skipBytes(2); // Characteristics

            if (sizeOfOptionalHeader > 0) {
                int optMagic = BinaryReader.readUInt16(raf);
                peHeader.setOptionalMagic(optMagic);
                boolean is64bit = (optMagic == 0x20B);

                raf.skipBytes(14); // Linker version, sizes
                peHeader.setEntryPoint(BinaryReader.readUInt32(raf));
                raf.skipBytes(4); // BaseOfCode

                if (!is64bit) {
                    raf.skipBytes(4); // BaseOfData
                    peHeader.setImageBase(BinaryReader.readUInt32(raf));
                } else {
                    peHeader.setImageBase(BinaryReader.readUInt64(raf));
                }

                raf.skipBytes(8); // Section/File alignment
                raf.skipBytes(16); // Versions
                peHeader.setSizeOfImage(BinaryReader.readUInt32(raf));
                raf.skipBytes(4); // SizeOfHeaders
            }

            peInfo.setPeHeader(peHeader);

            parseSections(raf, peInfo, peOffset, sizeOfOptionalHeader);
        }
    }

    // Metodo para parsear secciones
    private static void parseSections(RandomAccessFile raf, PEInfo peInfo,
                                      long peOffset, int sizeOfOptionalHeader) throws IOException {
        int numSections = peInfo.getPeHeader().getNumberOfSections();
        long sectionsOffset = peOffset + 24 + sizeOfOptionalHeader;

        for (int i = 0; i < numSections; i++) {
            raf.seek(sectionsOffset + (i * 40));

            String name = BinaryReader.readFixedString(raf, 8);
            Section section = new Section(name);

            section.setVirtualSize(BinaryReader.readUInt32(raf));
            section.setVirtualAddress(BinaryReader.readUInt32(raf));
            section.setRawSize(BinaryReader.readUInt32(raf));
            section.setRawPointer(BinaryReader.readUInt32(raf));

            raf.skipBytes(12);
            section.setCharacteristics(BinaryReader.readUInt32(raf));

            if (section.getRawSize() > 0 && section.getRawPointer() > 0) {
                long currentPos = raf.getFilePointer();
                raf.seek(section.getRawPointer());

                int dataSize = (int) Math.min(section.getRawSize(), 1024 * 1024); // Máx 1MB
                byte[] sectionData = BinaryReader.readBytes(raf, dataSize);
                section.setData(sectionData);
                section.setEntropy(EntropyCalculator.calculate(sectionData));
                section.setCompressionRatio(CompressionUtil.calculateCompressionRatio(sectionData));

                raf.seek(currentPos);
            }

            peInfo.addSection(section);
        }
    }

    // Metodo para leer bytes del archivo
    private static byte[] readFileBytes(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return fis.readAllBytes();
        }
    }
}
