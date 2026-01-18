package malware.model;

import java.io.File;
import java.util.*;

// Aquesta classe agrupa tota la informació extreta d’un executable PE

public class PEInfo {

    // Atributs
    private File file;
    private String fileName;
    private long fileSize;
    private String md5;
    private String sha1;
    private String sha256;
    private DOSHeader dosHeader;
    private PEHeader peHeader;
    private List<Section> sections;
    private List<StringEntry> strings;
    private List<ImportEntry> imports;
    private double entropy;

    // Constructor
    public PEInfo(File file) {
        this.file = file;
        this.fileName = file.getName();
        this.fileSize = file.length();
        this.sections = new ArrayList<>();
        this.strings = new ArrayList<>();
        this.imports = new ArrayList<>();
    }

    // Getters i setters
    public File getFile() {
        return file;
    }

    public String getFileName() {
        return fileName;
    }

    public long getFileSize() {
        return fileSize;
    }

    public String getMd5() {
        return md5;
    }

    public void setMd5(String md5) {
        this.md5 = md5;
    }

    public String getSha1() {
        return sha1;
    }

    public void setSha1(String sha1) {
        this.sha1 = sha1;
    }

    public String getSha256() {
        return sha256;
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    public DOSHeader getDosHeader() {
        return dosHeader;
    }

    public void setDosHeader(DOSHeader dosHeader) {
        this.dosHeader = dosHeader;
    }

    public PEHeader getPeHeader() {
        return peHeader;
    }

    public void setPeHeader(PEHeader peHeader) {
        this.peHeader = peHeader;
    }

    public List<Section> getSections() {
        return sections;
    }

    public void addSection(Section section) {
        this.sections.add(section);
    }

    public List<StringEntry> getStrings() {
        return strings;
    }

    public void addString(StringEntry string) {
        this.strings.add(string);
    }

    public List<ImportEntry> getImports() {
        return imports;
    }

    public void addImport(ImportEntry importEntry) {
        this.imports.add(importEntry);
    }

    public double getEntropy() {
        return entropy;
    }

    public void setEntropy(double entropy) {
        this.entropy = entropy;
    }

    // Et diu la mida del fitxer en bytes, KB o MB
    public String getFormattedFileSize() { 
        if (fileSize < 1024)
            return fileSize + " bytes";
        else if (fileSize < 1024 * 1024)
            return String.format("%.2f KB", fileSize / 1024.0);
        else 
            return String.format("%.2f MB", fileSize / (1024.0 * 1024.0));
    }
}
