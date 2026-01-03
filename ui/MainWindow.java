//importaciones internas


//librerias necesarias para la construccion de la GUI y vinculo -> "datos" <-> "UI"
import javax.imageio.*;
import javax.swing.*;
import java.awt.*;
import java.io.*;

//clase que conforma la ventana principal de la app

public class MainWindow extends JFrame {

    //componentes UI
    private JTree headersTree;
    private JTable stringsTable;
    private JTable importsTable;
    private JTextField stringSearchField;
    private JLabel stausLabel;


    //Detalles Frame ventana principal
    public MainWindow(){
        //Tiulo ventana
        setTitle("MalHunter");
        //Tamano predeterminado de la ventana ( en pixeles [ancho, alto] )
        setSize(1200, 800);
        //Cierra la ventana caso el user haga click en la "x" | ".EXIT_ON_CLOSE" cierra por completo
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        //Cierra la ventana en el medio de la pantalla -> "null" ( referencia al centro de la pantalla )
        setLocationRelativeTo(null);

        createUI();

    }

    private void createUI(){
        //Menu bar -> proximamente
        //createMenubar();

        JPanel mainPanel = new JPanel(new BorderLayout(10,10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        //Tabs 
        JTabbedPane tabs = new JTabbedPane();

        //Tab 1 -> Headers 
        //tabs.add("PE Headers", createHeadersPanel());

        //Tab 2 -> Strings
        //tabs.add("Strings", createStringsPanel());

        //Tab3 -> Imports y TTP's
        //tabs.add("Imports & TTp's", createImportsPanel());

        //Barra de estado 
        stausLabel = new JLabel("Ready");
        stausLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        mainPanel.add(tabs, BorderLayout.CENTER);
        mainPanel.add(stausLabel, BorderLayout.SOUTH);
        add(mainPanel);

        private void createMenubar(){};

        private JPanel createHeadersPanel(){};

        private JPanel createStringsPanel(){};

        private JPanel createImportsPanel(){};


    }


}

