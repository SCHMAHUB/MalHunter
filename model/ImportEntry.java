package malware.model;

import java.util.ArrayList;
import java.util.List;

// Aquesta classe guarda la informació de les DLL

public class ImportEntry {

    private String dllName;
    private List<FunctionInfo> functions;
    private boolean isSuspicious;
    private String category;
    private List<String> ttps;

    public ImportEntry(String dllName) {
        this.dllName = dllName;
        this.functions = new ArrayList<>();
        this.ttps = new ArrayList<>();
    }

    public String getDllName() {
        return dllName; // Return del nom
    }

    public List<FunctionInfo> getFunctions() {
        return functions; // Return de funcions importades
    }

    public void addFunction(FunctionInfo function) {
        this.functions.add(function); // Afegeix funció a la DLL
    }

    public boolean isSuspicious() {
        return isSuspicious; // Diu si la DLL és sospitosa
    }

    public void setSuspicious(boolean suspicious) {
        isSuspicious = suspicious; // Posa o treu la DLL de sospitosa
    }

    public String getCategory() {
        return category; // Return categoria de la DLL
    }

    public void setCategory(String category) {
        this.category = category; // Assigna categoria
    }

    public List<String> getTtps() {
        return ttps; // Return llista de TTPs
    }

    public void addTtp(String ttp) {
        this.ttps.add(ttp); // Afegeix una TTP
    }

    
    public int getSuspiciousFunctionCount() { // Return de numero de funcions sospitoses
        return (int) functions.stream() // Convertit en stream per a poder filtrar
                .filter(FunctionInfo::isSuspicious) // Filtra si es sospitos
                .count(); // Count per saber el numero
    }

    public static class FunctionInfo {

        private String name;
        private boolean isSuspicious;
        private String description;
        private String mitreTactic;
        private String mitreTechnique;
        
        public FunctionInfo(String name) { // Constructor
            this.name = name;
        }

        public String getName() {
            return name; // Return nom
        }

        public boolean isSuspicious() {
            return isSuspicious; // DIu si es sospitos
        }

        public void setSuspicious(boolean suspicious) {
            isSuspicious = suspicious; // Posa o treu la funció de sospitosa
        }

        public String getDescription() {
            return description; // Dona la descripció
        }

        public void setDescription(String description) {
            this.description = description; // Assigna descripció
        }

        public String getMitreTactic() {
            return mitreTactic; // Return la tàctica MITRE associada
        }

        public void setMitreTactic(String mitreTactic) {
            this.mitreTactic = mitreTactic; // Assigna tàctica MITRE
        }

        public String getMitreTechnique() {
            return mitreTechnique; // Return tècnica MITRE
        }

        public void setMitreTechnique(String mitreTechnique) {
            this.mitreTechnique = mitreTechnique; // Assigna tècnica MITRE
        }

        @Override
        public String toString() { // Return del nom de la funció i diu si és sospitosa
            return name + (isSuspicious ? " [SUSPICIOUS]" : "");
        }
    }
}