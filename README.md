# MalHunter Framework

> Framework de análisis estático de malware para archivos PE (Portable Executable)

[![Java](https://img.shields.io/badge/Java-17-orange.svg)](https://openjdk.org/)
[![Maven](https://img.shields.io/badge/Maven-4.0-blue.svg)](https://maven.apache.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Index

- [Descripción](#-descripción)
- [Características](#-características)
- [Arquitectura](#-arquitectura)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [Componentes Principales](#-componentes-principales)
- [Análisis Técnico](#-análisis-técnico)
- [Capturas de Pantalla](#-capturas-de-pantalla)

---

## Descripción

**MalHunter** es un framework de análisis estático de malware desarrollado en Java que permite examinar archivos ejecutables de Windows (formato PE). El proyecto implementa técnicas de análisis forense digital para detectar archivos maliciosos, funciones potencialmente peligrosas y patrones de evasión y detección de VM/Sandbox comúnmente utilizados por malware.

El framework extrae las siguientes informaciónes:
- Hashes criptográficos (MD5, SHA-1, SHA-256)
- Entropía de los headers (detección de ofuscación y aleatoriedad)
- Importaciones de DLLs y funciones que ejecuta
- "Strings" Cadenas de texto embebidas (ASCII/Unicode)
- Mapeo de TTP's (MITRE ATT&CK) y comportamiento

---

## Características

| Característica | Descripción |
|----------------|-------------|
| **Análisis de Cabeceras PE** | Parse  de DOS Header, PE Header y secciones |
| **Detección de Entropía** | Identificación de código comprimido/cifrado|
| **Extracción de Strings** | Recuperación de cadenas ASCII y Unicode con búsqueda en tiempo real |
| **Análisis de Importaciones** | Mapeo de funciones sospechosas a técnicas MITRE ATT&CK |
| **Interfaz Gráfica Intuitiva** | GUI Swing con 3 pestañas de análisis |
| **Compatibilidad Multi-Arquitectura** | Soporte para x86, x64, ARM y ARM64 |

---

## Arquitectura General

```
┌─────────────────────────────────────────┐
│         UI Layer (Swing)                 │
│      MainWindow (3-tab GUI)              │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│      Analysis Engines                    │
│  ┌──────────┐ ┌──────────┐ ┌─────────┐  │
│  │PEAnalyzer│ │  Import  │ │ String  │  │
│  │          │ │ Analyzer │ │Analyzer │  │
│  └──────────┘ └──────────┘ └─────────┘  │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│      Data Models (POJOs)                 │
│  PEInfo • Section • ImportEntry          │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│      Utility Layer                       │
│  BinaryReader • EntropyCalculator        │
└─────────────────────────────────────────┘
```

**Flujo:**
1. Usuario abre archivo PE → `MainWindow`
2. `PEAnalyzer` parsea estructura binaria → `PEInfo`
3. `StringAnalyzer` extrae strings embebidos
4. `ImportAnalyzer` detecta DLL's y TTP's
5. Resultados visualizados en interfaz tabular

---

## Estructura del Proyecto

```
MalHunter/
├── pom.xml                          # Configuración Maven
├── README.md                        # Este archivo
└── src/main/java/malware/
    ├── MalwareAnalyzerApp.java      # Punto de entrada
    ├── analyzer/
    │   ├── PEAnalyzer.java          # Motor de análisis PE
    │   ├── ImportAnalyzer.java      # Detección de TTPs
    │   └── StringAnalyzer.java      # Extractor de strings
    ├── model/
    │   ├── PEInfo.java              # Contenedor de resultados
    │   ├── DOSHeader.java           # Cabecera DOS/MZ
    │   ├── PEHeader.java            # Cabecera PE
    │   ├── Section.java             # Sección PE (.text, .data, etc.)
    │   ├── ImportEntry.java         # Entrada de importación DLL
    │   └── StringEntry.java         # String extraído
    ├── ui/
    │   └── MainWindow.java          # Interfaz gráfica principal
    └── util/
        ├── BinaryReader.java        # Lector binario 
        ├── EntropyCalculator.java   # Cálculo de entropía (Shannon)
        └── CompressionUtil.java     # Ratio de compresión
```

---

## Instalación

### Prerequisitos

- **Java Development Kit (JDK) 17+**
- **Apache Maven 3.6+**
```bash
sudo apt install maven 
```

### Compilación

```bash
# Clonar repositorio (si aplica)
git clone https://github.com/schmahub/MalHunter.git
cd MalHunter
mvn clean package
java -jar target/analyzer-4.0.jar

```

---

## Uso

1. **Abrir archivo PE:**
   - `Archivo → Abrir Archivo PE` (o `Ctrl+O`)
   - Seleccionar un ejecutable `.exe` o `.dll` de Windows

2. **Explorar pestañas:**
   - **PE Headers:** Información de cabeceras, hashes y secciones
   - **Strings:** Cadenas de texto con búsqueda en tiempo real
   - **Imports & TTPs:** Funciones importadas y técnicas MITRE ATT&CK

3. **Interpretación de resultados:**
   - **Entropía Alta (>7.0):** Posible cifrado/compresión
   - **Secciones Ejecutables+Escribibles:** Comportamiento sospechoso
   - **TTPs detectados:** Técnicas de ataque identificadas

---

## Componentes Principales

### PEAnalyzer

**Función:** Parseo de estructura PE y cálculo de hashes.

```java
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

```


- Soporta PE32 (32-bit) y PE32+ (64-bit)
- Calcula entropía por sección para detectar ofuscación
- Identifica arquitectura: x86, x64, ARM, ARM64

**Archivo:** `src/main/java/malware/analyzer/PEAnalyzer.java`

---

### ImportAnalyzer

**Función:** Análisis de importaciones y mapeo a MITRE ATT&CK.

```java
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

```

**Ejemplo de TTPs detectados:**

| Función | DLL | Técnica MITRE | Descripción |
|---------|-----|---------------|-------------|
| `CreateRemoteThread` | kernel32.dll | T1055 | Inyección de código en procesos |
| `SetWindowsHookEx` | user32.dll | T1056.004 | Keylogging mediante hooks |
| `InternetOpenUrl` | wininet.dll | T1071 | Comunicación C2 via HTTP |
| `CryptEncrypt` | crypt32.dll | T1027 | Cifrado de archivos (ransomware) |

**Archivo:** `src/main/java/malware/analyzer/ImportAnalyzer.java`

---

### StringAnalyzer

**Función:** Extracción de strings ASCII y Unicode.

```java
public class StringAnalyzer {
    private static final int MIN_STRING_LENGTH = 4;

    // Metodo para analizar los strings en un archivo binario
    public static void analyze(PEInfo peInfo) throws IOException {
        byte[] fileData = readFileBytes(peInfo.getFile());

        extractASCIIStrings(fileData, peInfo);

        extractUnicodeStrings(fileData, peInfo);
    }

    private static void extractASCIIStrings(byte[] data, PEInfo peInfo) {
        StringBuilder current = new StringBuilder();
        long startOffset = 0;

        for (int i = 0; i < data.length; i++) {
            byte b = data[i];

            if (isPrintableASCII(b)) {
                if (current.length() == 0) {
                    startOffset = i;
                }
                current.append((char) b);
            } else {
                if (current.length() >= MIN_STRING_LENGTH) {
                    peInfo.addString(new StringEntry(startOffset, current.toString(), "ASCII"));
                }
                current.setLength(0);
            }
        }

        if (current.length() >= MIN_STRING_LENGTH) {
            peInfo.addString(new StringEntry(startOffset, current.toString(), "ASCII"));
        }
    }

    private static void extractUnicodeStrings(byte[] data, PEInfo peInfo) {
        StringBuilder current = new StringBuilder();
        long startOffset = 0;

        for (int i = 0; i < data.length - 1; i += 2) {
            int lowByte = data[i] & 0xFF;
            int highByte = data[i + 1] & 0xFF;

            // Unicode UTF-16 LE: highByte debe ser 0 para caracteres ASCII
            if (highByte == 0 && isPrintableASCII((byte) lowByte)) {
                if (current.length() == 0) {
                    startOffset = i;
                }
                current.append((char) lowByte);
            } else {
                if (current.length() >= MIN_STRING_LENGTH) {
                    String str = current.toString();
                    // Evitar duplicados con ASCII
                    boolean isDuplicate = peInfo.getStrings().stream()
                            .anyMatch(s -> s.getValue().equals(str));

                    if (!isDuplicate) {
                        peInfo.addString(new StringEntry(startOffset, str, "Unicode"));
                    }
                }
                current.setLength(0);
            }
        }

        if (current.length() >= MIN_STRING_LENGTH) {
            String str = current.toString();
            boolean isDuplicate = peInfo.getStrings().stream()
                    .anyMatch(s -> s.getValue().equals(str));

            if (!isDuplicate) {
                peInfo.addString(new StringEntry(startOffset, str, "Unicode"));
            }
        }
    }
```

**Archivo:** `src/main/java/malware/analyzer/StringAnalyzer.java`

---

### EntropyCalculator

**Función:** Cálculo de entropía de Shannon para detección de cifrado.

```java
public static double calculate(byte[] data){
        if(data == null || data.length == 0){
            return 0.0;
        }
        // Frequencia de cada valor de byte (0-255)
        int[] frequency = new int[256];
        for (byte b : data) {
            frequency[b & 0xFF]++;
        }
        double entropy = 0.0;
        int dataLength = data.length;

        for (int count : frequency) {
            if (count == 0){
                continue;
            }

            double probability = (double) count / dataLength; // Al ser count y data lenght ints la division sera entre ints y la tenemos que convertir nosotros a double.
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }

        return entropy;
    }
```

**Interpretación:**

| Entropía | Nivel | Significado |
|----------|-------|-------------|
| < 3.0 | Muy Baja | Datos altamente redundantes |
| 3.0 - 5.0 | Baja | Código ejecutable normal |
| 5.0 - 6.0 | Media | Datos comprimidos |
| 6.0 - 7.0 | Alta | Posible compresión |
| > 7.0 | Muy Alta | **Cifrado/Ofuscación (Sospechoso)** |

**Archivo:** `src/main/java/malware/util/EntropyCalculator.java`

---

### Section (Modelo)

**Función:** Representación de secciones PE con detección de anomalías.

```java
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
```

**Características sospechosas:**
- **Sección .text con entropía 7.5:** Código cifrado
- **Sección .data ejecutable+escribible:** Code injection
- **Ratio compresión 5%:** Datos aleatorios/cifrados

**Archivo:** `src/main/java/malware/model/Section.java`

---

### MainWindow (UI)

**Función:** Interfaz gráfica con 3 pestañas de análisis.

```java
public MainWindow() {
        setTitle("MalHunter");
        //Tamano predeterminado de la ventana ( en pixeles [ancho, alto] )
        setSize(1200, 800);
        //Cierra la ventana caso el user haga click en la "x" | ".EXIT_ON_CLOSE" cierra por completo
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        //Cierra la ventana en el medio de la pantalla -> "null" ( referencia al centro de la pantalla )
        setLocationRelativeTo(null);

        createUI();
    }
}
```

**Características UI:**
- Visualización de entropía con códigos de color
- Búsqueda en tiempo real de strings
- Tabla de TTPs con categorización MITRE
- Atajos de teclado (`Ctrl+O`, `Ctrl+Q`)

**Archivo:** `src/main/java/malware/ui/MainWindow.java`

---

## Análisis Técnico

### Detección de Packers

```java
// Detectar UPX, ASPack, etc.
if (section.getEntropy() > 7.0 && section.getName().equals(".text")) {
    System.out.println("Posible ejecutable empaquetado");
}
```

### Detección de Ransomware

```java
// Funciones criptográficas + extensiones de archivo
if (imports.contains("CryptEncrypt") &&
    strings.contains(".encrypted") || strings.contains(".locked")) {
    System.out.println("Posible ransomware detectado");
}
```

### Detección de Keyloggers

```java
// Hooks de teclado
if (imports.contains("SetWindowsHookExA") &&
    imports.contains("GetAsyncKeyState")) {
    System.out.println("Posible keylogger - MITRE T1056.004");
}
```

---

## Capturas de Pantalla

### Pestaña 1: PE Headers
```
|>>>Archivo: malware.exe (245 KB)
├──  MD5: a3d5f1e2b4c6...
├──  SHA-1: 7f2e1a9c5b8d...
├──  SHA-256: 3c5a9f2e7d1b...
├──  Entropía Global: 6.8
├──  Arquitectura: x86 (32-bit)
└──  Secciones:
    ├── .text   [Entropía: 7.2 ]  SOSPECHOSO
    ├── .data   [Entropía: 3.1 ]
    └── .rsrc   [Entropía: 5.4 ]
```

### Pestaña 2: Strings
```
┌─────────┬─────────┬─────────────────────────────┐
│ Offset  │  Type   │ String                      │
├─────────┼─────────┼─────────────────────────────┤
│ 0x1A20  │ ASCII   │ http://malicious-c2.com     │
│ 0x2F40  │ Unicode │ C:\Windows\System32\cmd.exe │
│ 0x3B80  │ ASCII   │ GET /download.php?id=       │
└─────────┴─────────┴─────────────────────────────┘
```

### Pestaña 3: Imports & TTPs
```
┌─────────────┬──────────────────┬────────────────┬──────────┐
│ DLL         │ Función          │ MITRE Tactic   │ Técnica  │
├─────────────┼──────────────────┼────────────────┼──────────┤
│ kernel32    │ VirtualAllocEx   │ Defense Evasion│ T1055    │
│ user32      │ SetWindowsHookEx │ Collection     │ T1056.004│
│ wininet     │ InternetOpenUrl  │ C2             │ T1071    │
└─────────────┴──────────────────┴────────────────┴──────────┘
```

---

## Tecnologías Utilizadas

| Tecnología | Versión | Finalidad |
|------------|---------|-----------|
| Java | 17 | Lenguaje de programación |
| Maven | 4.0 | Gestión de dependencias y build |
| Swing | Built-in | Framework de interfaz gráfica |
| Apache Commons Codec | 1.16.0 | Hashing criptográfico |

---

## Contexto Académico

Este proyecto fue desarrollado como trabajo final de **segundo año de Ciberseguridad** en la asignatura de **Programación Orientada a Objetos en Java**.

**Objetivos de aprendizaje:**
- Manipulación de archivos binarios
- Diseño de arquitectura por capas (UI → Logic → Utils)
- Implementación de patrones de diseño (Model-View)
- Integración de librerías externas (Maven)
- Desarrollo de interfaces gráficas con Swing

**Nota sobre IA:** Algunas funcionalidades complejas fueron implementadas mediante sistemas basados en reglas predefinidas generadas por LLM, dada la complejidad del proyecto y nuestro deseo de hacerlo posible.



## Referencias

- [PE Format Specification - Microsoft](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Entropía de Shannon](https://en.wikipedia.org/wiki/Entropy_(information_theory))
- [PE-Tree Tool](https://github.com/blackberry/pe_tree)



## Licencia

Este proyecto es material académico desarrollado para fines educativos y libre de uso por cualquier persona.Contiene una MIT License.



## Developers

Proyecto desarrollado como parte de la carrera Universitária de **Ciberseguridad**
- vicent510
- rogervalles-cmyk
- SCHMAHUB

---

<div align="center">

**MalHunter - Static Malware Analysis Framework**

*"Know the threat to stop the threat"*

*Dev Team*

</div>