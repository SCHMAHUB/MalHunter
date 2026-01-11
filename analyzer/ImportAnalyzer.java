package analyzer;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import malware.model.ImportEntry;
import malware.model.ImportEntry.FunctionInfo;
import malware.model.PEInfo;

// Analizador de los imports
public class ImportAnalyzer {

    private static final Map<String, DLLCapability> DLL_CAPABILITIES = new HashMap<>();

    static {
        initializeCapabilities();
    }

    public static void analyze(PEInfo peInfo) throws IOException {
        byte[] fileData = readFileBytes(peInfo.getFile());
        String content = new String(fileData, StandardCharsets.ISO_8859_1);

        // Buscar DLLs conocidas
        for (Map.Entry<String, DLLCapability> entry : DLL_CAPABILITIES.entrySet()) {
            String dllName = entry.getKey();
            DLLCapability capability = entry.getValue();

            if (content.toLowerCase().contains(dllName.toLowerCase())) {
                ImportEntry importEntry = new ImportEntry(dllName);
                importEntry.setCategory(capability.category);
                importEntry.setSuspicious(capability.suspicious);

                // Buscar funciones de esta DLL
                for (FunctionCapability funcCap : capability.functions) {
                    if (content.contains(funcCap.name)) {
                        FunctionInfo funcInfo = new FunctionInfo(funcCap.name);
                        funcInfo.setSuspicious(funcCap.suspicious);
                        funcInfo.setDescription(funcCap.description);
                        funcInfo.setMitreTactic(funcCap.mitreTactic);
                        funcInfo.setMitreTechnique(funcCap.mitreTechnique);

                        importEntry.addFunction(funcInfo);

                        // Agregar TTP si es sospechoso
                        if (funcCap.suspicious && funcCap.mitreTechnique != null) {
                            String ttp = funcCap.mitreTactic + ": " + funcCap.mitreTechnique;
                            if (!importEntry.getTtps().contains(ttp)) {
                                importEntry.addTtp(ttp);
                            }
                        }
                    }
                }

                if (!importEntry.getFunctions().isEmpty()) {
                    peInfo.addImport(importEntry);
                }
            }
        }
    }

    // Falta por completar las capabilities, seguramente se haga con IA debido a que es una tarea repetitiva que no se trata de programación sino de buscar información en Mittre

    private static void initializeCapabilities() {
        // KERNEL32.DLL
        DLLCapability kernel32 = new DLLCapability("kernel32.dll", "System Operations", false);
        kernel32.addFunction("CreateFile", false, "Open/create file", null, null);
        kernel32.addFunction("WriteFile", false, "Write to file", null, null);
        kernel32.addFunction("ReadFile", false, "Read from file", null, null);
        kernel32.addFunction("DeleteFile", false, "Delete file", null, null);
        kernel32.addFunction("CreateProcess", true, "Execute new process","Execution", "T1106 - Native API");
        DLL_CAPABILITIES.put("kernel32.dll", kernel32);

        // NTDLL.DLL 
        DLLCapability ntdll = new DLLCapability("ntdll.dll", "Low-level APIs", true);
        ntdll.addFunction("NtCreateThread", true, "Create thread",
                "Defense Evasion", "T1055 - Process Injection");
        DLL_CAPABILITIES.put("ntdll.dll", ntdll);

        // USER32.DL
        DLLCapability user32 = new DLLCapability("user32.dll", "User Interface", false);
        user32.addFunction("MessageBox", false, "Display message", null, null);
        DLL_CAPABILITIES.put("user32.dll", user32);

        // ADVAPI32.DLL
        DLLCapability advapi32 = new DLLCapability("advapi32.dll", "Registry/Services", true);
        advapi32.addFunction("CreateService", true, "Create service", "Persistence", "T1543.003 - Windows Service");
        advapi32.addFunction("StartService", true, "Start service", "Execution", "T1569.002 - Service Execution");
        DLL_CAPABILITIES.put("advapi32.dll", advapi32);

        // WS2_32.DLL
        DLLCapability ws2_32 = new DLLCapability("ws2_32.dll", "Network Operations", true);
        ws2_32.addFunction("WSAStartup", true, "Initialize Winsock", "Command and Control", "T1071 - Application Layer Protocol");
        DLL_CAPABILITIES.put("ws2_32.dll", ws2_32);

        // WININET.DLL
        DLLCapability wininet = new DLLCapability("wininet.dll", "Internet Operations", true);
        wininet.addFunction("InternetOpen", true, "Initialize internet", "Command and Control", "T1071.001 - Web Protocols");
        DLL_CAPABILITIES.put("wininet.dll", wininet);

        // URLMON.DLL
        DLLCapability urlmon = new DLLCapability("urlmon.dll", "URL Operations", true);
        urlmon.addFunction("URLDownloadToFile", true, "Download file from URL", "Command and Control", "T1105 - Ingress Tool Transfer");
        DLL_CAPABILITIES.put("urlmon.dll", urlmon);

        // CRYPT32.DLL
        DLLCapability crypt32 = new DLLCapability("crypt32.dll", "Cryptography", true);
        crypt32.addFunction("CryptEncrypt", true, "Encrypt data", "Impact", "T1486 - Data Encrypted for Impact");
        crypt32.addFunction("CryptDecrypt", true, "Decrypt data", "Defense Evasion", "T1140 - Deobfuscate/Decode Files");
        DLL_CAPABILITIES.put("crypt32.dll", crypt32);

        // SHELL32.DLL 
        DLLCapability shell32 = new DLLCapability("shell32.dll", "Shell Operations", false);
        shell32.addFunction("ShellExecute", true, "Execute file/command", "Execution", "T1106 - Native API");
        shell32.addFunction("SHGetFolderPath", false, "Get folder path", null, null);
        DLL_CAPABILITIES.put("shell32.dll", shell32);

        // PSAPI.DLL
        DLLCapability psapi = new DLLCapability("psapi.dll", "Process Information", true);
        psapi.addFunction("EnumProcesses", true, "Enumerate processes", "Discovery", "T1057 - Process Discovery");
        psapi.addFunction("GetModuleInformation", true, "Get module info", "Discovery", "T1057 - Process Discovery");
        DLL_CAPABILITIES.put("psapi.dll", psapi);

        // MSVCRT.DLL
        DLLCapability msvcrt = new DLLCapability("msvcrt.dll", "C Runtime", false);
        msvcrt.addFunction("malloc", false, "Allocate memory", null, null);
        msvcrt.addFunction("free", false, "Free memory", null, null);
        msvcrt.addFunction("system", true, "Execute command", "Execution", "T1059 - Command and Scripting Interpreter");
        DLL_CAPABILITIES.put("msvcrt.dll", msvcrt);
    }

    private static byte[] readFileBytes(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return fis.readAllBytes();
        }
    }

    // Clase para cada DLL capability
    private static class DLLCapability {
        String name;
        String category;
        boolean suspicious;
        List<FunctionCapability> functions;

        DLLCapability(String name, String category, boolean suspicious) {
            this.name = name;
            this.category = category;
            this.suspicious = suspicious;
            this.functions = new ArrayList<>();
        }

        void addFunction(String name, boolean suspicious, String description,
                        String mitreTactic, String mitreTechnique) {
            functions.add(new FunctionCapability(name, suspicious, description,
                    mitreTactic, mitreTechnique));
        }
    }

    // Clase para cada función de las diferentes capabilities de las DLL
    private static class FunctionCapability {
        String name;
        boolean suspicious;
        String description;
        String mitreTactic;
        String mitreTechnique;

        FunctionCapability(String name, boolean suspicious, String description,
                          String mitreTactic, String mitreTechnique) {
            this.name = name;
            this.suspicious = suspicious;
            this.description = description;
            this.mitreTactic = mitreTactic;
            this.mitreTechnique = mitreTechnique;
        }
    }
}
