package com.tech_titans.view;

import com.tech_titans.controller.HomeController;
import com.tech_titans.service.EncryptionService;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.Scanner;

public class HomeView extends JFrame {
    private HomeController controller;
    private JPanel mainPanel; // Panel to load different content dynamically
    private JProgressBar progressBar;
    private String ivString = "";
    private String key = "";
    // for enc
    // private JPanel mainContentPanel; // for enc
    private File selectedFile;
    private JRadioButton fileRadioButton;
    private JRadioButton newfileRadioButton;
    private JTextArea inputTextArea;
    private JTextArea outputTextArea;
    private JComboBox<String> cipherModeComboBox;
    private JComboBox<String> paddingComboBox;
    private JTextField ivTextField;
    private JComboBox<String> keySizeComboBox;
    private JPasswordField secretKeyField;
    private JRadioButton base64RadioButton;
    private JRadioButton hexRadioButton;
    private JButton generateIvButton;
    private JButton generateKeyButton;
    private JProgressBar operationProgressBar;
    private JLabel fileInfoLabel;

    public HomeView() {
        setTitle("File Encryption & Decryption");
        setSize(800, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        // Initialize Controller
        controller = new HomeController(this);

        // Create Menu Bar
        JMenuBar menuBar = new JMenuBar();

        JMenu fileMenu = new JMenu("File");
        JMenu encryptMenu = new JMenu("Encryption");
        JMenu decryptMenu = new JMenu("Decryption");
        JMenu settingsMenu = new JMenu("Settings");
        JMenu helpMenu = new JMenu("Help");

        // Create Menu Items
        JMenuItem openFileItem = new JMenuItem("Open File");
        JMenuItem exitItem = new JMenuItem("Exit");
        JMenuItem encryptOption = new JMenuItem("Encrypt File");
        JMenuItem encryptOption2 = new JMenuItem("Encrypt Text");
        JMenuItem decryptOption = new JMenuItem("Decrypt File");
        JMenuItem decryptOption2 = new JMenuItem("Decrypt Text");
        JMenuItem settingsOption = new JMenuItem("Preferences");
        JMenuItem aboutOption = new JMenuItem("About");

        // Add items to their respective menus
        fileMenu.add(openFileItem);
        fileMenu.add(exitItem);
        encryptMenu.add(encryptOption);
        encryptMenu.add(encryptOption2);
        decryptMenu.add(decryptOption);
        decryptMenu.add(decryptOption2);
        settingsMenu.add(settingsOption);
        helpMenu.add(aboutOption);

        // Add menus to menu bar
        menuBar.add(fileMenu);
        menuBar.add(encryptMenu);
        menuBar.add(decryptMenu);
        menuBar.add(settingsMenu);
        menuBar.add(helpMenu);

        setJMenuBar(menuBar);

        // Progress Bar at Bottom
        progressBar = new JProgressBar();
        progressBar.setString("Ready");
        progressBar.setStringPainted(true);
        add(progressBar, BorderLayout.SOUTH);

        // Main Blank Panel (Where UI Elements Will Be Shown on Action)
        mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout());
        add(mainPanel, BorderLayout.CENTER);

        // Attach event listeners to Controller
        openFileItem.addActionListener(controller::handleOpenFile);
        exitItem.addActionListener(e -> System.exit(0));
        encryptOption.addActionListener(controller::handleFileEncrypt);
        // encryptOption2.addActionListener(controller::handleTextEncrypt);
        decryptOption.addActionListener(controller::handleDecrypt);
        settingsOption.addActionListener(controller::handleSettings);
        aboutOption.addActionListener(controller::handleHelp);

        setVisible(true);
    }

    public JPanel EncryptionView(File selectedFile){
        
        // Top section - File/Text selection
        JPanel topPanel = new JPanel(new BorderLayout());
        JPanel radioPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        ButtonGroup inputTypeGroup = new ButtonGroup();
        fileRadioButton = new JRadioButton("Your Selected File", selectedFile != null);
        newfileRadioButton = new JRadioButton("Select New File", selectedFile == null);
        
        inputTypeGroup.add(fileRadioButton);
        inputTypeGroup.add(newfileRadioButton);
        
        radioPanel.add(fileRadioButton);
        radioPanel.add(newfileRadioButton);
        
        
        JButton openFileButton = new JButton("Browse");
        openFileButton.addActionListener(e -> controller.handleOpenFile(e));
        openFileButton.setEnabled(newfileRadioButton.isSelected());
        

        JPanel fileInfoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fileInfoLabel = new JLabel(selectedFile != null ? 
            "Selected file: " + selectedFile.getName() : "No file selected");
        fileInfoPanel.add(fileInfoLabel);
        
        JPanel browsePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        browsePanel.add(openFileButton);
        
        JPanel filePanel = new JPanel(new BorderLayout());
        filePanel.add(fileInfoPanel, BorderLayout.CENTER);
        filePanel.add(browsePanel, BorderLayout.EAST);
        
        topPanel.add(radioPanel, BorderLayout.NORTH);
        topPanel.add(filePanel, BorderLayout.CENTER);
        
        // Center section - Input/Output Text Areas
        JPanel centerPanel = new JPanel(new GridLayout(2, 1, 0, 10));
        
        // Input panel
        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.setBorder(BorderFactory.createTitledBorder("Input Text"));
        
        inputTextArea = new JTextArea(8, 40);
        inputTextArea.setLineWrap(true);
        inputTextArea.setWrapStyleWord(true);
        JScrollPane inputScrollPane = new JScrollPane(inputTextArea);
        inputPanel.add(inputScrollPane, BorderLayout.CENTER);
        StringBuilder text = new StringBuilder();
        if (selectedFile != null) {
            try (Scanner myReader = new Scanner(selectedFile)) {
                while (myReader.hasNextLine()) {
                    text.append(myReader.nextLine()).append("\n"); // Preserve line breaks
                }
            } catch (FileNotFoundException e) {
                updateStatus("An error occurred.");
                e.printStackTrace();
            }
        }
        System.out.println("File Selected: " + selectedFile);
        System.out.println("File Content: " + text);
        inputTextArea.setText(text.toString());
        inputTextArea.setEditable(false);
        
        // Output panel
        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.setBorder(BorderFactory.createTitledBorder("Encrypted Output"));
        
        outputTextArea = new JTextArea(8, 40);
        outputTextArea.setLineWrap(true);
        outputTextArea.setWrapStyleWord(true);
        JScrollPane outputScrollPane = new JScrollPane(outputTextArea);
        outputPanel.add(outputScrollPane, BorderLayout.CENTER);
        
        centerPanel.add(inputPanel);
        centerPanel.add(outputPanel);
        
        // Right section - Encryption options
        JPanel rightPanel = new JPanel();
        rightPanel.setLayout(new BoxLayout(rightPanel, BoxLayout.Y_AXIS));
        rightPanel.setBorder(BorderFactory.createTitledBorder("Encryption Options"));
        
        // Cipher Mode
        JPanel cipherModePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        cipherModePanel.add(new JLabel("Cipher Mode:"));
        
        cipherModeComboBox = new JComboBox<>(new String[]{"ECB", "CBC", "CTR", "GCM"});
        cipherModeComboBox.setSelectedItem("CBC"); // Default to CBC for better security
        cipherModePanel.add(cipherModeComboBox);
        JButton cipherHelpButton = new JButton("?");
        cipherHelpButton.setMargin(new Insets(0, 5, 0, 5));
        cipherHelpButton.addActionListener(e -> showHelp("Cipher Mode", 
            "ECB - Electronic Codebook: Simple but less secure\n" +
            "CBC - Cipher Block Chaining: More secure, requires IV\n" +
            "CTR - Counter: Good for parallelization, requires IV\n" +
            "GCM - Galois/Counter Mode: Authenticated encryption, requires IV"));
        cipherModePanel.add(cipherHelpButton);
        
        // Padding
        JPanel paddingPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        paddingPanel.add(new JLabel("Padding:"));
        
        paddingComboBox = new JComboBox<>(new String[]{"PKCS5Padding", "NoPadding"});
        paddingPanel.add(paddingComboBox);
        JButton paddingHelpButton = new JButton("?");
        paddingHelpButton.setMargin(new Insets(0, 5, 0, 5));
        paddingHelpButton.addActionListener(e -> showHelp("Padding", 
            "PKCS5Padding - Standard padding scheme\n" +
            "NoPadding - No padding (data must be multiple of block size)"));
        paddingPanel.add(paddingHelpButton);
        
        // IV
        JPanel ivPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        ivPanel.add(new JLabel("IV:"));
        
        ivTextField = new JTextField(16);
        ivPanel.add(ivTextField);
        
        generateIvButton = new JButton("Generate IV");
        generateIvButton.addActionListener(e -> {
            try {
                byte[] iv = EncryptionService.generateIV();
                // Convert to a 16-char string for display
                ivString = Base64.getEncoder().encodeToString(iv);
                ivTextField.setText(ivString);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, 
                    "Error generating IV: " + ex.getMessage(), 
                    "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        ivPanel.add(generateIvButton);
        
        JButton ivHelpButton = new JButton("?");
        ivHelpButton.setMargin(new Insets(0, 5, 0, 5));
        ivHelpButton.addActionListener(e -> showHelp("Initialization Vector", 
            "IV is required for CBC, CTR, and GCM modes.\n" +
            "It should be 16 bytes (characters) long and unique for each encryption."));
        ivPanel.add(ivHelpButton);
        
        // Key Size
        JPanel keySizePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        keySizePanel.add(new JLabel("Key Size:"));
        
        keySizeComboBox = new JComboBox<>(new String[]{"128", "192", "256"});
        keySizePanel.add(keySizeComboBox);
        JButton keySizeHelpButton = new JButton("?");
        keySizeHelpButton.setMargin(new Insets(0, 5, 0, 5));
        keySizeHelpButton.addActionListener(e -> showHelp("Key Size", 
            "Larger keys provide more security but may be slower.\n" +
            "128 - Standard AES key size\n" +
            "192 - Increased security\n" +
            "256 - Maximum security"));
        keySizePanel.add(keySizeHelpButton);
        
        // Secret Key
        JPanel secretKeyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        secretKeyPanel.add(new JLabel("Secret Key:"));
        
        secretKeyField = new JPasswordField(16);
        secretKeyPanel.add(secretKeyField);
        
        generateKeyButton = new JButton("Generate Key");
        generateKeyButton.addActionListener(e -> {
            try {
                int keySize = Integer.parseInt((String) keySizeComboBox.getSelectedItem());
                key = EncryptionService.generateKey(keySize);
                secretKeyField.setText(key);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, 
                    "Error generating key: " + ex.getMessage(), 
                    "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
        secretKeyPanel.add(generateKeyButton);
        
        JButton keyHelpButton = new JButton("?");
        keyHelpButton.setMargin(new Insets(0, 5, 0, 5));
        keyHelpButton.addActionListener(e -> showHelp("Secret Key", 
            "The secret key should be kept private.\n" +
            "It must be the same for encryption and decryption."));
        secretKeyPanel.add(keyHelpButton);
        
        // Output Format
        JPanel outputFormatPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        outputFormatPanel.add(new JLabel("Output Format:"));
        
        ButtonGroup formatGroup = new ButtonGroup();
        base64RadioButton = new JRadioButton("Base64", true);
        hexRadioButton = new JRadioButton("Hex");
        
        formatGroup.add(base64RadioButton);
        formatGroup.add(hexRadioButton);
        
        outputFormatPanel.add(base64RadioButton);
        outputFormatPanel.add(hexRadioButton);
        
        JButton formatHelpButton = new JButton("?");
        formatHelpButton.setMargin(new Insets(0, 5, 0, 5));
        formatHelpButton.addActionListener(e -> showHelp("Output Format", 
            "Base64 - Compact representation using 64 characters\n" +
            "Hex - Hexadecimal representation (longer but only uses 0-9, A-F)"));
        outputFormatPanel.add(formatHelpButton);
        
        // Add all option panels to right panel
        rightPanel.add(cipherModePanel);
        rightPanel.add(paddingPanel);
        rightPanel.add(ivPanel);
        rightPanel.add(keySizePanel);
        rightPanel.add(secretKeyPanel);
        rightPanel.add(outputFormatPanel);
        
        // Operation Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        
        JButton encryptButton = new JButton("Encrypt");
        encryptButton.addActionListener(e -> controller.handleActualFileEncrypt(selectedFile,cipherModeComboBox,paddingComboBox,ivString,keySizeComboBox,key,formatGroup));
        
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {
            // inputTextArea.setText("");
            // outputTextArea.setText("");
            ivTextField.setText("");
            secretKeyField.setText("");
        });
        
        JButton showoutButton = new JButton("Show Encrypted Output");
        showoutButton.addActionListener(e -> {
            try {
                // Get the encrypted file path (assuming default location is used)
                String encryptedFilePath = selectedFile.getPath() + ".encrypted";
                File encryptedFile = new File(encryptedFilePath);
        
                if (!encryptedFile.exists()) {
                    JOptionPane.showMessageDialog(null, "No encrypted file found!", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
        
                // Read the encrypted file
                String encryptedContent = readEncryptedFile(encryptedFile);
        
                // Display the encrypted content in the text area
                outputTextArea.setText(encryptedContent);
                outputTextArea.setEditable(false);
        
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Error reading encrypted file: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        // Progress Bar
        operationProgressBar = new JProgressBar();
        operationProgressBar.setStringPainted(true);
        operationProgressBar.setString("Ready");
        
        buttonPanel.add(encryptButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(showoutButton);
        // Main layout
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(topPanel, BorderLayout.NORTH);
        
        JPanel centerRightPanel = new JPanel(new BorderLayout());
        centerRightPanel.add(centerPanel, BorderLayout.CENTER);
        centerRightPanel.add(rightPanel, BorderLayout.EAST);
        
        contentPanel.add(centerRightPanel, BorderLayout.CENTER);
        
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(buttonPanel, BorderLayout.NORTH);
        bottomPanel.add(operationProgressBar, BorderLayout.SOUTH);
        
        contentPanel.add(bottomPanel, BorderLayout.SOUTH);
        
        fileRadioButton.addItemListener(e -> {
            if (fileRadioButton.isSelected()) {
                openFileButton.setEnabled(false);
            }
        });
        
        newfileRadioButton.addItemListener(e -> {
            if (newfileRadioButton.isSelected()) {
                openFileButton.setEnabled(true);
            }
        });

        return contentPanel;
    }

    private String readEncryptedFile(File file) throws IOException {
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        return Base64.getEncoder().encodeToString(fileBytes);
    }

    // Method to update the main panel dynamically
    public void setMainPanelContent(JPanel newContent) {
        mainPanel.removeAll(); // Clear previous content
        mainPanel.add(newContent, BorderLayout.CENTER);
        mainPanel.revalidate();
        mainPanel.repaint();
    }

    public void updateStatus(String message) {
        progressBar.setString(message);
    }

    public void showMessage(String message) {
        JOptionPane.showMessageDialog(this, message);
    }

    // Getter for selected file
    public File getSelectedFile() {
        return selectedFile;
    }

    public JProgressBar getProgressBar() {
        return operationProgressBar;
    }
    
    public JRadioButton getFileRadioButton() {
        return fileRadioButton;
    }
    
    public JRadioButton getnewfileRadioButton() {
        return newfileRadioButton;
    }
    
    public JTextArea getInputTextArea() {
        return inputTextArea;
    }
    
    public JTextArea getOutputTextArea() {
        return outputTextArea;
    }
    
    public JComboBox<String> getCipherModeComboBox() {
        return cipherModeComboBox;
    }
    
    public JComboBox<String> getPaddingComboBox() {
        return paddingComboBox;
    }
    
    public JTextField getIvTextField() {
        return ivTextField;
    }
    
    public JComboBox<String> getKeySizeComboBox() {
        return keySizeComboBox;
    }
    
    public JPasswordField getSecretKeyField() {
        return secretKeyField;
    }
    
    public JRadioButton getBase64RadioButton() {
        return base64RadioButton;
    }
    
    public JRadioButton getHexRadioButton() {
        return hexRadioButton;
    }
    
    public JButton getGenerateIvButton() {
        return generateIvButton;
    }
    
    public JButton getGenerateKeyButton() {
        return generateKeyButton;
    }
    
    public void setSelectedFile(File file) {
        this.selectedFile = file;
        fileInfoLabel.setText(file != null ? "Selected file: " + file.getName() : "No file selected");
        if (file == null) {
            inputTextArea.setText("");
        }
    }
    
    private void showHelp(String title, String message) {
        JOptionPane.showMessageDialog(this, message, title, JOptionPane.INFORMATION_MESSAGE);
    }
}