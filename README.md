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

### Compilación

```bash
# Clonar repositorio (si aplica)
git clone <repository-url>
cd MalHunter
java MalwareAnalyzerApp.java
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
public PEInfo analyze(File file) throws IOException {
    try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
        // 1. Calcular hashes criptográficos
        calculateHashes();

        // 2. Parsear cabecera DOS (MZ)
        parseDOSHeader(raf);

        // 3. Parsear cabecera PE
        parsePEHeader(raf);

        // 4. Extraer secciones (.text, .data, etc.)
        parseSections(raf);

        // 5. Calcular entropía global
        peInfo.setEntropy(EntropyCalculator.calculate(fileBytes));

        return peInfo;
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
public List<ImportEntry> analyzeImports(PEInfo peInfo, byte[] fileBytes) {
    // Base: 14 DLLs con funciones categorizadas
    Map<String, Map<String, String>> dllCapabilities = buildDllCapabilities();

    // Detectar imports sospechosos
    for (ImportEntry entry : entries) {
        if (dllCapabilities.containsKey(dllName)) {
            String category = categorizeFunction(funcName);
            String[] mitre = getMitreTTP(funcName);

            functionInfo.setSuspicious(true);
            functionInfo.setMitreTactic(mitre[0]);   // ej. "Defense Evasion"
            functionInfo.setMitreTechnique(mitre[1]); // ej. "T1055"
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
public List<StringEntry> extractStrings(byte[] data) {
    List<StringEntry> strings = new ArrayList<>();

    // 1. Extraer strings ASCII
    strings.addAll(extractASCII(data));

    // 2. Extraer strings Unicode (UTF-16 LE)
    strings.addAll(extractUnicode(data));

    // 3. Eliminar duplicados
    return deduplicateStrings(strings);
}

private List<StringEntry> extractASCII(byte[] data) {
    // Buscar secuencias de caracteres imprimibles (min. 4 chars)
    for (int i = 0; i < data.length; i++) {
        if (isPrintable(data[i])) {
            StringBuilder sb = new StringBuilder();
            while (i < data.length && isPrintable(data[i])) {
                sb.append((char) data[i++]);
            }
            if (sb.length() >= 4) {
                strings.add(new StringEntry(offset, sb.toString(), "ASCII"));
            }
        }
    }
}
```

**Archivo:** `src/main/java/malware/analyzer/StringAnalyzer.java`

---

### EntropyCalculator

**Función:** Cálculo de entropía de Shannon para detección de cifrado.

```java
public static double calculate(byte[] data) {
    int[] freq = new int[256];
    for (byte b : data) {
        freq[b & 0xFF]++;
    }

    double entropy = 0.0;
    for (int count : freq) {
        if (count > 0) {
            double p = (double) count / data.length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
    }
    return entropy; // Rango: 0.0 - 8.0 bits/byte
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
public boolean isSuspicious() {
    // Detectar secciones sospechosas
    boolean highEntropy = entropy > 7.0;
    boolean execWritable = isExecutable() && isWritable();
    boolean lowCompression = (compressionRatio >= 0 && compressionRatio < 20);

    return highEntropy || execWritable || lowCompression;
}

// Colores en formato Hex.
public String getEntropyColor() {
    if (entropy < 3.0) return "#3498db";      // Azul
    if (entropy < 5.0) return "#2ecc71";      // Verde
    if (entropy < 7.0) return "#f39c12";      // Naranja
    return "#e74c3c";                         // Rojo (Sospechoso)
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
private void buildUI() {
    JTabbedPane tabbedPane = new JTabbedPane();

    // Pestaña 1: Headers PE + Entropía
    tabbedPane.addTab("PE Headers", buildPEHeadersPanel());

    // Pestaña 2: Strings con búsqueda
    tabbedPane.addTab("Strings", buildStringsPanel());

    // Pestaña 3: Imports + MITRE ATT&CK
    tabbedPane.addTab("Imports & TTPs", buildImportsPanel());
}

private void analyzeFile(File file) {
    SwingWorker<PEInfo, Void> worker = new SwingWorker<>() {
        protected PEInfo doInBackground() {
            PEAnalyzer analyzer = new PEAnalyzer(file);
            return analyzer.analyze(file);
        }

        protected void done() {
            displayResults(get());
        }
    };
    worker.execute();
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