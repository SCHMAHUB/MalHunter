package malware.model;

import java.util.ArrayList;
import java.util.List;

// Aquesta classe guarda la informació de les DLL

public class ImportEntry {

    // Atributs
    private String dllName;
    private List<FunctionInfo> functions;
    private boolean isSuspicious;
    private String category;
    private List<String> ttps;

    // Constructor
    public ImportEntry(String dllName) {
        this.dllName = dllName;
        this.functions = new ArrayList<>();
        this.ttps = new ArrayList<>();
    }

    // Getters i setters
    public String getDllName() {
        return dllName;
    }

    public List<FunctionInfo> getFunctions() {
        return functions;
    }

    public void addFunction(FunctionInfo function) {
        this.functions.add(function);
    }

    public boolean isSuspicious() {
        return isSuspicious; 
    }

    public void setSuspicious(boolean suspicious) {
        isSuspicious = suspicious;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category; 
    }

    public List<String> getTtps() {
        return ttps;
    }

    public void addTtp(String ttp) {
        this.ttps.add(ttp);
    }

    // Return de numero de funcions sospitoses
    public int getSuspiciousFunctionCount() {
        return (int) functions.stream()
                .filter(FunctionInfo::isSuspicious)
                .count();
    }

    // Classe interna
    public static class FunctionInfo {

        // Atributs
        private String name;
        private boolean isSuspicious;
        private String description;
        private String mitreTactic;
        private String mitreTechnique;

        // Constructor
        public FunctionInfo(String name) { 
            this.name = name;
        }

        // Getters i setters
        public String getName() {
            return name;
        }

        public boolean isSuspicious() {
            return isSuspicious;
        }

        public void setSuspicious(boolean suspicious) {
            isSuspicious = suspicious;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getMitreTactic() {
            return mitreTactic;
        }

        public void setMitreTactic(String mitreTactic) {
            this.mitreTactic = mitreTactic;
        }

        public String getMitreTechnique() {
            return mitreTechnique;
        }

        public void setMitreTechnique(String mitreTechnique) {
            this.mitreTechnique = mitreTechnique;
        }

        // Return del nom de la funció i si és sospitosa
        @Override
        public String toString() {
            return name + (isSuspicious ? " [SUSPICIOUS]" : "");
        }
    }
}
