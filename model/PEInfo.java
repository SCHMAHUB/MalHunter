package malware.model;

import java.io.File;
import java.util.*;


public class PEInfo { // Aquesta classe agrupa tota la informació extreta d’un executable PE

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

    public PEInfo(File file) {
        this.file = file;
        this.fileName = file.getName();
        this.fileSize = file.length();
        this.sections = new ArrayList<>();
        this.strings = new ArrayList<>();
        this.imports = new ArrayList<>();
    }

    public File getFile() {
        return file; // Return del fitxer
    }

    public String getFileName() {
        return fileName; // Return del nom del fitxer
    }

    public long getFileSize() {
        return fileSize; // Return de la mida del fitxer
    }

    public String getMd5() {
        return md5; // Return hash MD5
    }

    public void setMd5(String md5) {
        this.md5 = md5; // Assigna hash MD5
    }

    public String getSha1() {
        return sha1; // Return hash SHA-1
    }

    public void setSha1(String sha1) {
        this.sha1 = sha1; // Assigna hash SHA-1
    }

    public String getSha256() {
        return sha256; // Return hash SHA-256
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256; // Assigna hash SHA-256
    }

    public DOSHeader getDosHeader() {
        return dosHeader; // Return DOS Header
    }

    public void setDosHeader(DOSHeader dosHeader) {
        this.dosHeader = dosHeader; // Assigna DOS Header
    }

    public PEHeader getPeHeader() {
        return peHeader; // Return PE Header
    }

    public void setPeHeader(PEHeader peHeader) {
        this.peHeader = peHeader; // Assigna PE Header
    }

    public List<Section> getSections() {
        return sections; // Return llista de seccions
    }

    public void addSection(Section section) {
        this.sections.add(section); // Afegeix secció
    }

    public List<StringEntry> getStrings() {
        return strings; // Return llista de strings
    }

    public void addString(StringEntry string) {
        this.strings.add(string); // Afegeix string
    }

    public List<ImportEntry> getImports() {
        return imports; // Return llista d’imports
    }

    public void addImport(ImportEntry importEntry) {
        this.imports.add(importEntry); // Afegeix import
    }

    public double getEntropy() {
        return entropy; // Return entropia
    }

    public void setEntropy(double entropy) {
        this.entropy = entropy; // Assigna entropia
    }

    public String getFormattedFileSize() { // Et diu la mida del fitxer en bytes, KB o MB
        if (fileSize < 1024) // Comprova si la mida del fitxer és menor de 1024 bytes
            return fileSize + " bytes"; // Et diu la mida i li afegeix bytes si està per sota de 1024
        else if (fileSize < 1024 * 1024) // Si no era el primer cas, comprova si és menor d’1 MB
            return String.format("%.2f KB", fileSize / 1024.0); // Converteix la mida a kilobytes (KB)
        else 
            return String.format("%.2f MB", fileSize / (1024.0 * 1024.0)); // Converteix la mida a megabytes (MB)
    }
}
