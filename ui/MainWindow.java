//importaciones internas
import MalHunter.analyzer.*;
import MalHunter.model.*;

//librerias necesarias para la construccion de la GUI y vinculo -> "datos" <-> "UI"
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

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
        
        createMenubar();

        JPanel mainPanel = new JPanel(new BorderLayout(10,10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        //Tabs 
        JTabbedPane tabs = new JTabbedPane();

        //Tab 1 -> Headers 
        tabs.add("PE Headers", createHeadersPanel());

        //Tab 2 -> Strings
        tabs.add("Strings", createStringsPanel());

        //Tab3 -> Imports y TTP's
        tabs.add("Imports & TTp's", createImportsPanel());

        //Barra de estado 
        stausLabel = new JLabel("Ready");
        stausLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        mainPanel.add(tabs, BorderLayout.CENTER);
        mainPanel.add(stausLabel, BorderLayout.SOUTH);
        add(mainPanel);
    }

    //Objeto barra menu superior
    private void createMenubar(){
        JMenuBar menuBar = new JMenu("File");
        JMenuItem openItem = new JMenuItem("Open PE file...");
        openItem.addActionListener(e -> openFile());
        openItem.setAccelerator(KeyStroke.getKeyStroke("control O"));
        fileMenu.add(openItem);

        JMenuItem exitItem = new JMenuItem("Exit");
        exitItem.addActionListener(e -> System.exit(0));
        exitItem.setAccelerator(KeyStroke.getKeyStroke("control Q"));

        menuBar.add(fileMenu);
        setJMenuBar(menuBar);
    }


    //Objeto panel Headers 
    private JPanel createHeadersPanel(){
        //Panel con imagen de fondo
        BackgroundPanel panel = new BackgroundPanel();
        panel.setLayout(new BorderLayout());

        headersTree = new JTree(new DefaultMutableTreeNode("No file loaded"));
        headersTree.setFont(new Font("Courier New", Font.BOLD, 14));
        headersTree.setOpaque(false);

        //Config. de los colores para los valores de la entropia del PE
        ColoredTreeCellRenderer renderer = new ColoredTreeCellRenderer();
        headersTree.setCellRenderer(renderer);

        JScrollPane scrollPane = new JScrollPane(headersTree);
        scrollPane.setOpaque(false);
        scrollPane.getViewport().setOpaque(false);
        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;

    }

    //Seccion para la personalizacion de los colores de la entropia del PE



    //Objeto panel Strings
    private JPanel createStringsPanel(){
        JPanel panel = new JPanel(new BorderLayout(5,5));

        //Campo de entrada de busqueda en tiempo real 
        JPanel searchPanel = new JPanel(new BorderLayout(5,5));
        searchPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        JLabel searchLabel = new JLabel("Search:");
        stringSearchField = new JTextField();

        //Busqueda en tiempo real con 'DocumentListener' -> actualiza a medida que buscamos cadenas de String
        stringSearchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e ) { searchStrings(); }

            @Override
            public void removeUpdate(DocumentEvent e ) { searchStrings(); }

            @Override
            public void changeUpdate(DocumentEvent e ) { searchStrings(); }
        });

        //Resetea la busqueda mostrando todos los Strings 
        JButton showAllButton = new JButton("Show All");
        showAllButton.addActionListener(e -> displayAllStrings());
        searchPanel.add(searchLabel, BorderLayout.WEST);
        searchPanel.add(stringSearchField, BorderLayout.CENTER);
        searchPanel.add(showAllButton, BorderLayout.EAST);

        //Display tabla de Strings resultante -> "Type" -> tipo de String , EJ:'Unicode','ASCII' | NO EDITABLE
        String[] columns = {"#", "Address", "Type", "String"};
        DefaultTableModel model = new DefaultTableModel(columns, 0){
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; //Tabla NO EDITABLE | VALORES ESTAICOS 

            }
        };

        stringsTable = new JTable(model);
        stringsTable.setFont(new Font("Courier New", Font.BOLD, 14));
        // Logica para tener las columnas fijas 
        stringsTable.getTableHeader().setReorderingAllowed(false);
        JScrollPane scrollPane = new JScrollPane(stringsTable);
        panel.add(searchPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;


    }

    //Objeto panel Importaciones
    private JPanel createImportsPanel(){
        JPanel panel = new JPanel(new BorderLayout());

        String[] columns = {"DLL", "Function", "Category", "MITRE Tactic", "MITRE Technique", "Status"};
        DefaultTableModel model = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; //NO EDITABLE | VALORES ESTAICOS 
            }
        };

        importsTable = new JTable(model);
        importsTable.setFont(new Font("Courier New", Font.BOLD, 14));
        // Logica para tener las columnas fijas 
        importsTable.getTableHeader().setReorderingAllowed(false);
        JScrollPane scrollPane = new JScrollPane(importsTable);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;

    };


    


}

