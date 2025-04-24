package com.tech_titans.view;

import com.tech_titans.controller.HomeController;
import com.tech_titans.model.EncryptionModel;
import com.tech_titans.service.EncryptionService;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Array;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Scanner;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;

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

    public JPanel createSendFilePanel() {
        JPanel sendPanel = new JPanel(new BorderLayout(10, 10));
        sendPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        // North Panel - Instructions
        JPanel instructionPanel = new JPanel(new BorderLayout());
        JLabel instructionLabel = new JLabel("<html><h2>Send Encrypted File</h2>" +
                "<p>This feature allows you to send encrypted files to other users via TCP/IP.</p></html>");
        instructionPanel.add(instructionLabel, BorderLayout.CENTER);
        sendPanel.add(instructionPanel, BorderLayout.NORTH);

        // Center Panel - File and Destination Info
        JPanel formPanel = new JPanel();
        formPanel.setLayout(new BoxLayout(formPanel, BoxLayout.Y_AXIS));

        // File Selection
        JPanel fileSelectionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel fileLabel = new JLabel("Select File to Send:");
        JTextField filePathField = new JTextField(30);
        filePathField.setEditable(false);
        JButton browseButton = new JButton("Browse");

        fileSelectionPanel.add(fileLabel);
        fileSelectionPanel.add(filePathField);
        fileSelectionPanel.add(browseButton);

        // IP Address input
        JPanel ipPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel ipLabel = new JLabel("Recipient's IP Address:");
        JTextField ipField = new JTextField(15);

        ipPanel.add(ipLabel);
        ipPanel.add(ipField);

        // Port input
        JPanel portPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel portLabel = new JLabel("Port Number:");
        JTextField portField = new JTextField("9999", 6);

        // portPanel.add(portLabel);
        // portPanel.add(portField);

        // Add all panels to form
        formPanel.add(fileSelectionPanel);
        formPanel.add(ipPanel);
        formPanel.add(portPanel);

        // Add some spacing
        formPanel.add(Box.createVerticalStrut(20));

        // Send button and progress
        JPanel sendActionPanel = new JPanel(new BorderLayout());
        JButton sendButton = new JButton("Send File");
        JProgressBar sendProgressBar = new JProgressBar(0, 100);
        sendProgressBar.setStringPainted(true);
        sendProgressBar.setString("Ready to send");

        sendActionPanel.add(sendButton, BorderLayout.NORTH);
        sendActionPanel.add(sendProgressBar, BorderLayout.SOUTH);

        formPanel.add(sendActionPanel);

        // Status messages
        JPanel statusPanel = new JPanel(new BorderLayout());
        JTextArea statusArea = new JTextArea(5, 40);
        statusArea.setEditable(false);
        JScrollPane statusScrollPane = new JScrollPane(statusArea);
        statusPanel.add(new JLabel("Status:"), BorderLayout.NORTH);
        statusPanel.add(statusScrollPane, BorderLayout.CENTER);

        formPanel.add(Box.createVerticalStrut(20));
        formPanel.add(statusPanel);

        sendPanel.add(formPanel, BorderLayout.CENTER);

        // Set up action listeners
        browseButton.addActionListener(e -> controller.handleSelectFileToSend(filePathField));
        sendButton.addActionListener(e -> {
            try {
                String ip = ipField.getText().trim();
                int port = Integer.parseInt(portField.getText().trim());
                controller.handleSendFile(filePathField.getText(), ip, port, sendProgressBar, statusArea);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, "Invalid port number", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        return sendPanel;
    }

    private String getTemporaryIPv6Address() {
        try {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = networkInterfaces.nextElement();

                // Skip loopback and non-active interfaces
                if (networkInterface.isLoopback() || !networkInterface.isUp()) {
                    continue;
                }

                Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
                while (inetAddresses.hasMoreElements()) {
                    InetAddress inetAddress = inetAddresses.nextElement();

                    // Check if the address is IPv6
                    if (inetAddress instanceof java.net.Inet6Address) {
                        java.net.Inet6Address ipv6Address = (java.net.Inet6Address) inetAddress;

                        // Skip link-local addresses and loopback
                        if (!ipv6Address.isLinkLocalAddress() && !ipv6Address.isLoopbackAddress()) {
                            // Check if it's likely a temporary address (not EUI-64/MAC-derived)
                            byte[] addressBytes = ipv6Address.getAddress();
                            if ((addressBytes[8] & 0x02) != 0x02) {
                                return ipv6Address.getHostAddress();
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public JPanel createReceiveFilePanel() {
        JPanel receivePanel = new JPanel(new BorderLayout(10, 10));
        receivePanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        // North Panel - Instructions
        JPanel instructionPanel = new JPanel(new BorderLayout());
        JLabel instructionLabel = new JLabel("<html><h2>Receive Encrypted File</h2>" +
                "<p>This feature allows you to receive encrypted files from other users via TCP/IP.</p></html>");
        instructionPanel.add(instructionLabel, BorderLayout.CENTER);
        receivePanel.add(instructionPanel, BorderLayout.NORTH);

        // Center Panel - Server Controls
        JPanel controlPanel = new JPanel();
        controlPanel.setLayout(new BoxLayout(controlPanel, BoxLayout.Y_AXIS));

        // Save location
        JPanel saveLocationPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel saveLabel = new JLabel("Save Location:");
        JTextField savePathField = new JTextField(30);
        savePathField.setEditable(false);
        String defaultSavePath = System.getProperty("user.home") + File.separator + "Downloads";
        savePathField.setText(defaultSavePath);
        JButton browseButton = new JButton("Browse");

        saveLocationPanel.add(saveLabel);
        saveLocationPanel.add(savePathField);
        saveLocationPanel.add(browseButton);

        // Server information
        JPanel serverInfoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel serverLabel = new JLabel("Your IP Addresses:");
        serverInfoPanel.add(serverLabel);

        // IPv4 Address field
        JTextField ipv4Field = new JTextField(15);
        ipv4Field.setEditable(false);
        serverInfoPanel.add(new JLabel("IPv4:"));
        serverInfoPanel.add(ipv4Field);

        // IPv6 Address field
        JTextField ipv6Field = new JTextField(30);
        ipv6Field.setEditable(false);
        serverInfoPanel.add(new JLabel("IPv6:"));
        serverInfoPanel.add(ipv6Field);

        JLabel portLabel = new JLabel("Port:");
        JTextField portField = new JTextField("9999", 6);
        portField.setEditable(false);
        // serverInfoPanel.add(portLabel);
        // serverInfoPanel.add(portField);

        // Fill in the IP addresses
        try {
            // Get IPv4 address
            ipv4Field.setText(InetAddress.getLocalHost().getHostAddress());

            // Get temporary IPv6 address
            String temporaryIPv6 = getTemporaryIPv6Address();
            if (temporaryIPv6 != null && !temporaryIPv6.isEmpty()) {
                ipv6Field.setText(temporaryIPv6);
            } else {
                ipv6Field.setText("No temporary IPv6 address found");
            }
        } catch (Exception e) {
            ipv4Field.setText("Could not determine IP");
            ipv6Field.setText("Could not determine IPv6");
        }

        // Server controls
        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton startServerButton = new JButton("Start Receiving");
        JButton stopServerButton = new JButton("Stop Receiving");
        stopServerButton.setEnabled(false);

        controlsPanel.add(startServerButton);
        controlsPanel.add(stopServerButton);

        // Add all panels to form
        controlPanel.add(saveLocationPanel);
        controlPanel.add(serverInfoPanel);
        controlPanel.add(controlsPanel);

        // Add some spacing
        controlPanel.add(Box.createVerticalStrut(20));

        // Progress bar
        JProgressBar receiveProgressBar = new JProgressBar(0, 100);
        receiveProgressBar.setStringPainted(true);
        receiveProgressBar.setString("Server not running");
        controlPanel.add(receiveProgressBar);

        // Status messages
        JPanel statusPanel = new JPanel(new BorderLayout());
        JTextArea statusArea = new JTextArea(5, 40);
        statusArea.setEditable(false);
        JScrollPane statusScrollPane = new JScrollPane(statusArea);
        statusPanel.add(new JLabel("Status:"), BorderLayout.NORTH);
        statusPanel.add(statusScrollPane, BorderLayout.CENTER);

        controlPanel.add(Box.createVerticalStrut(20));
        controlPanel.add(statusPanel);

        receivePanel.add(controlPanel, BorderLayout.CENTER);

        // Set up action listeners
        browseButton.addActionListener(e -> controller.handleSelectSaveLocation(savePathField));
        startServerButton.addActionListener(e -> {
            controller.handleStartReceiveServer(savePathField.getText(), receiveProgressBar, statusArea);
            startServerButton.setEnabled(false);
            stopServerButton.setEnabled(true);
        });
        stopServerButton.addActionListener(e -> {
            controller.handleStopReceiveServer(statusArea);
            startServerButton.setEnabled(true);
            stopServerButton.setEnabled(false);
            receiveProgressBar.setString("Server stopped");
        });

        return receivePanel;
    }

    // Helper method to save encryption details to a file
    public void saveEncryptionDetails2(File saveFile, JComboBox<String> cipherModeComboBox,
            JComboBox<String> paddingComboBox, String ivString,
            JComboBox<String> keySizeComboBox, String key,
            ButtonGroup formatGroup) throws IOException {
        try (FileWriter writer = new FileWriter(saveFile)) {
            writer.write("--- ENCRYPTION DETAILS ---\n\n");
            writer.write("Cipher Mode: " + cipherModeComboBox.getSelectedItem() + "\n");
            writer.write("Padding: " + paddingComboBox.getSelectedItem() + "\n");
            writer.write("IV: " + ivString + "\n");
            writer.write("Key Size: " + keySizeComboBox.getSelectedItem() + "\n");
            writer.write("Secret Key: " + key + "\n");

            String format = null;
            Enumeration<AbstractButton> buttons = formatGroup.getElements();
            while (buttons.hasMoreElements()) {
                AbstractButton button = buttons.nextElement();
                if (button.isSelected()) {
                    format = button.getActionCommand();
                    break;
                }
            }
            writer.write("Output Format: " + format + "\n");
        }
    }

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
        JMenu sharingMenu = new JMenu("File Transfer");
        JMenu settingsMenu = new JMenu("Settings");
        JMenu helpMenu = new JMenu("Help");

        // Create Menu Items
        JMenuItem home = new JMenuItem("Home");
        JMenuItem openFileItem = new JMenuItem("Open File");
        JMenuItem keyConverter = new JMenuItem("Key Converter");
        JMenuItem exitItem = new JMenuItem("Exit");
        JMenuItem encryptOption = new JMenuItem("Encrypt File");
        JMenuItem encryptOption2 = new JMenuItem("Encrypt Text");
        JMenuItem decryptOption = new JMenuItem("Decrypt File");
        JMenuItem decryptOption2 = new JMenuItem("Decrypt Text");
        JMenuItem settingsOption = new JMenuItem("Preferences");
        JMenuItem aboutOption = new JMenuItem("About");
        JMenuItem sendMenuItem = new JMenuItem("Send File");
        JMenuItem recivMenuItem = new JMenuItem("receive File");

        // Add items to their respective menus
        fileMenu.add(home);
        fileMenu.add(openFileItem);
        fileMenu.add(keyConverter);
        fileMenu.add(exitItem);
        encryptMenu.add(encryptOption);
        encryptMenu.add(encryptOption2);
        decryptMenu.add(decryptOption);
        decryptMenu.add(decryptOption2);
        settingsMenu.add(settingsOption);
        helpMenu.add(aboutOption);
        sharingMenu.add(sendMenuItem);
        sharingMenu.add(recivMenuItem);

        // Add menus to menu bar
        menuBar.add(fileMenu);
        menuBar.add(encryptMenu);
        menuBar.add(decryptMenu);
        menuBar.add(settingsMenu);
        menuBar.add(sharingMenu);
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
        home.addActionListener(controller::handleHome);
        openFileItem.addActionListener(controller::handleOpenFile);
        keyConverter.addActionListener(controller::handleKeyConvertions);
        exitItem.addActionListener(e -> System.exit(0));
        encryptOption.addActionListener(controller::handleFileEncrypt);
        encryptOption2.addActionListener(controller::handleTextEncrypt);
        decryptOption.addActionListener(controller::handleFileDecrypt);
        decryptOption2.addActionListener(controller::handleTextDecrypt);
        settingsOption.addActionListener(controller::handleSettings);
        aboutOption.addActionListener(controller::handleHelp);
        // Add these lines to your existing constructor code where you set up menu
        // handlers
        sendMenuItem.addActionListener(controller::handleSendFile);
        recivMenuItem.addActionListener(controller::handleReceiveFile);
        controller.handleHelp(null);
        setVisible(true);

    }

    public JPanel mainHomeFrame() {
        JPanel mhomePanel = new JPanel();
        mhomePanel.add(new JLabel("Starts exploring by clicking on Help and Navigate through Menus..."));
        return mhomePanel;
    }

    public JPanel EncryptionView(File selectedFile) {

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
        fileInfoLabel = new JLabel(
                selectedFile != null ? "Selected file: " + selectedFile.getName() : "No file selected");
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
        // change this function to work as byte reader
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

        cipherModeComboBox = new JComboBox<>(new String[] { "ECB", "CBC", "CTR", "GCM" });
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

        paddingComboBox = new JComboBox<>(new String[] { "PKCS5Padding", "NoPadding" });
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
        ivTextField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                String ivText = ivTextField.getText().trim(); // Trim whitespace
                System.out.println("Focus Lost Event Triggered"); // Debugging step

                if (ivText.length() != 16) {
                    // JOptionPane.showMessageDialog(ivTextField,
                    //         "IV must be exactly 16 characters long!",
                    //         "Invalid IV", JOptionPane.ERROR_MESSAGE);
                    // ivTextField.requestFocus(); // Bring focus back
                    updateStatus("IV must be exactly 16 characters long! Invalid IV");
                } else {
                    byte[] temp = ivTextField.getText().getBytes();
                    System.out.println(java.util.Arrays.toString(temp));
                    ivString = Base64.getEncoder().encodeToString(temp);
                }
            }
        });

        generateIvButton = new JButton("Generate IV");
        generateIvButton.addActionListener(e -> {
            try {
                byte[] iv = EncryptionService.generateIV();
                // Convert to a 16-char string for display
                ivString = Base64.getEncoder().encodeToString(iv);
                ivTextField.setText(ivString);
                ivTextField.setEditable(false);
                ivTextField.setEnabled(false);
                updateStatus("Done");
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

        keySizeComboBox = new JComboBox<>(new String[] { "128", "192", "256" });
        keySizePanel.add(keySizeComboBox);
        JButton keySizeHelpButton = new JButton("?");
        keySizeHelpButton.setMargin(new Insets(0, 5, 0, 5));
        keySizeHelpButton.addActionListener(e -> showHelp("Key Size",
                "Larger keys provide more security but may be slower.\n" +
                        "128 - Standard AES key size (16 chars)\n" +
                        "192 - Increased security (24 chars)\n" +
                        "256 - Maximum security (32 chars)"));
        keySizePanel.add(keySizeHelpButton);

        // Secret Key
        JPanel secretKeyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        secretKeyPanel.add(new JLabel("Secret Key:"));

        secretKeyField = new JPasswordField(16);
        secretKeyPanel.add(secretKeyField);

        keySizeComboBox.addActionListener(e -> {
            int selectedSize = Integer.parseInt((String) keySizeComboBox.getSelectedItem());
            int requiredLength = selectedSize / 8; // 128 -> 16, 192 -> 24, 256 -> 32
            secretKeyField.setColumns(requiredLength);
            secretKeyField.setText(""); // Clear the field when size changes
        });

        // Add Focus Listener to Validate Key Length
        secretKeyField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                int selectedSize = Integer.parseInt((String) keySizeComboBox.getSelectedItem());
                int requiredLength = selectedSize / 8;
                String keyText = new String(secretKeyField.getPassword()).trim();

                if (keyText.length() != requiredLength) {
                    // JOptionPane.showMessageDialog(secretKeyField,
                    //         "Key must be exactly " + requiredLength + " characters long!",
                    //         "Invalid Key Length", JOptionPane.ERROR_MESSAGE);
                    // secretKeyField.requestFocus();
                    updateStatus("Key must be exactly " + requiredLength + " characters long! Invalid Key Length");
                } else {
                    char[] a = secretKeyField.getPassword();
                    String s = String.valueOf(a);
                    byte[] t = s.getBytes();
                    key = Base64.getEncoder().encodeToString(t);
                }
            }
        });

        generateKeyButton = new JButton("Generate Key");
        generateKeyButton.addActionListener(e -> {
            try {
                int keySize = Integer.parseInt((String) keySizeComboBox.getSelectedItem());
                key = EncryptionService.generateKey(keySize);
                secretKeyField.setText(key);
                secretKeyField.setEditable(false);
                secretKeyField.setEnabled(false);
                updateStatus("Done");
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
        base64RadioButton.setActionCommand("Base64");
        hexRadioButton = new JRadioButton("Hex");
        hexRadioButton.setActionCommand("Hex");

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
        encryptButton.addActionListener(e -> controller.handleActualFileEncrypt(selectedFile, cipherModeComboBox,
                paddingComboBox, ivString, keySizeComboBox, key, formatGroup));

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {
            // inputTextArea.setText("");
            outputTextArea.setText("");
            ivTextField.setText("");
            secretKeyField.setText("");
            ivTextField.setEditable(true);
            ivTextField.setEnabled(true);
            secretKeyField.setEditable(true);
            secretKeyField.setEnabled(true);
        });

        JButton showoutButton = new JButton("Show Encrypted Output");
        showoutButton.addActionListener(e -> {
            try {
                String originalFileName = selectedFile.getName();
                String directory = selectedFile.getParent();
                File base64File = null;
                File hexFile = null;
                String outputFormat = formatGroup.getSelection().getActionCommand();
                // Construct possible file names
                if (outputFormat.equals("Base64")) { base64File = new File(directory, "b64_encrypted_" + originalFileName);} 
                else{ hexFile = new File(directory, "hex_encrypted_" + originalFileName);}

                File encryptedFile;

                if (base64File != null) {
                    encryptedFile = base64File;
                } else if (hexFile != null) {
                    encryptedFile = hexFile;
                } else {
                    JOptionPane.showMessageDialog(null, "Encrypted file not found (neither Base64 nor Hex).", "Error",
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }
                StringBuilder t = new StringBuilder();
                try (Scanner myReader = new Scanner(encryptedFile)) {
                    while (myReader.hasNextLine()) {
                        t.append(myReader.nextLine()).append("\n"); // Preserve line breaks
                    }
                } catch (FileNotFoundException eo) {
                    updateStatus("An error occurred.");
                    eo.printStackTrace();
                }
                // String content = new String(Files.readAllBytes(encryptedFile.toPath()), StandardCharsets.UTF_8);
                String content = t.toString();
                outputTextArea.setText(content);
                outputTextArea.setEditable(false);

            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Error reading encrypted file: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        });

        JButton savekeyButton = new JButton("Save Key Details");
        savekeyButton.addActionListener(e -> {
            try {
                // Prompt the user to select a save location
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Save Encryption Details");
                fileChooser.setSelectedFile(new File("Encryption_Details.txt"));

                int userSelection = fileChooser.showSaveDialog(null);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File saveFile = fileChooser.getSelectedFile();

                    // Write encryption details to file
                    saveEncryptionDetails(saveFile, cipherModeComboBox, paddingComboBox, ivString, keySizeComboBox, key,
                            formatGroup);

                    JOptionPane.showMessageDialog(null, "Encryption details saved successfully!", "Success",
                            JOptionPane.INFORMATION_MESSAGE);
                }

            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Error saving encryption details: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        });

        // Progress Bar
        operationProgressBar = new JProgressBar();
        operationProgressBar.setStringPainted(true);
        operationProgressBar.setString("Selecting the Encrypting Parameters.");

        buttonPanel.add(encryptButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(showoutButton);
        buttonPanel.add(savekeyButton);
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

    public JPanel TextEncryptionView() {
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
        inputTextArea.setEditable(true);

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

        cipherModeComboBox = new JComboBox<>(new String[] { "ECB", "CBC", "CTR", "GCM" });
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

        paddingComboBox = new JComboBox<>(new String[] { "PKCS5Padding", "NoPadding" });
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
        ivTextField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                String ivText = ivTextField.getText().trim(); // Trim whitespace
                System.out.println("Focus Lost Event Triggered"); // Debugging step

                if (ivText.length() != 16) {
                    // JOptionPane.showMessageDialog(ivTextField,
                    //         "IV must be exactly 16 characters long!",
                    //         "Invalid IV", JOptionPane.ERROR_MESSAGE);
                    // ivTextField.requestFocus(); // Bring focus back
                    updateStatus("IV must be exactly 16 characters long! Invalid IV");
                } else {
                    byte[] temp = ivTextField.getText().getBytes();
                    System.out.println(java.util.Arrays.toString(temp));
                    ivString = Base64.getEncoder().encodeToString(temp);
                }
            }
        });

        generateIvButton = new JButton("Generate IV");
        generateIvButton.addActionListener(e -> {
            try {
                byte[] iv = EncryptionService.generateIV();
                // Convert to a 16-char string for display
                ivString = Base64.getEncoder().encodeToString(iv);
                ivTextField.setText(ivString);
                ivTextField.setEditable(false);
                ivTextField.setEnabled(false);
                updateStatus("Done");
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

        keySizeComboBox = new JComboBox<>(new String[] { "128", "192", "256" });
        keySizePanel.add(keySizeComboBox);
        JButton keySizeHelpButton = new JButton("?");
        keySizeHelpButton.setMargin(new Insets(0, 5, 0, 5));
        keySizeHelpButton.addActionListener(e -> showHelp("Key Size",
                "Larger keys provide more security but may be slower.\n" +
                        "128 - Standard AES key size (16 chars)\n" +
                        "192 - Increased security (24 chars)\n" +
                        "256 - Maximum security (32 chars)"));
        keySizePanel.add(keySizeHelpButton);

        // Secret Key
        JPanel secretKeyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        secretKeyPanel.add(new JLabel("Secret Key:"));

        secretKeyField = new JPasswordField(16);
        secretKeyPanel.add(secretKeyField);

        keySizeComboBox.addActionListener(e -> {
            int selectedSize = Integer.parseInt((String) keySizeComboBox.getSelectedItem());
            int requiredLength = selectedSize / 8; // 128 -> 16, 192 -> 24, 256 -> 32
            secretKeyField.setColumns(requiredLength);
            secretKeyField.setText(""); // Clear the field when size changes
        });

        // Add Focus Listener to Validate Key Length
        secretKeyField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                int selectedSize = Integer.parseInt((String) keySizeComboBox.getSelectedItem());
                int requiredLength = selectedSize / 8;
                String keyText = new String(secretKeyField.getPassword()).trim();

                if (keyText.length() != requiredLength) {
                    // JOptionPane.showMessageDialog(secretKeyField,
                    //         "Key must be exactly " + requiredLength + " characters long!",
                    //         "Invalid Key Length", JOptionPane.ERROR_MESSAGE);
                    // // secretKeyField.requestFocus();
                    updateStatus("Key must be exactly " + requiredLength + " characters long! Invalid Key Length");
                } else {
                    char[] a = secretKeyField.getPassword();
                    String s = String.valueOf(a);
                    byte[] t = s.getBytes();
                    key = Base64.getEncoder().encodeToString(t);
                }
            }
        });

        generateKeyButton = new JButton("Generate Key");
        generateKeyButton.addActionListener(e -> {
            try {
                int keySize = Integer.parseInt((String) keySizeComboBox.getSelectedItem());
                key = EncryptionService.generateKey(keySize);
                secretKeyField.setText(key);
                secretKeyField.setEditable(false);
                secretKeyField.setEnabled(false);
                updateStatus("Done");
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
        base64RadioButton.setActionCommand("Base64");
        hexRadioButton = new JRadioButton("Hex");
        hexRadioButton.setActionCommand("Hex");

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
        encryptButton.addActionListener(e -> {
            // controller.handleActualFileEncrypt(selectedFile,cipherModeComboBox,paddingComboBox,ivString,keySizeComboBox,key,formatGroup)
            try {
                if (inputTextArea.getText() == null) {
                    JOptionPane.showMessageDialog(null, "No Text found for Encryption!", "Error",
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }

                String encryptedTextContent = controller.handleActualTextEncrypt(inputTextArea, cipherModeComboBox,
                        paddingComboBox, ivString, keySizeComboBox, key, formatGroup);

                // Display the encrypted content in the text area
                outputTextArea.setText(encryptedTextContent);
                outputTextArea.setEditable(false);

            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Error reading encrypted file: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        });

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {
            // inputTextArea.setText("");
            outputTextArea.setText("");
            ivTextField.setText("");
            ivTextField.setEditable(true);
            ivTextField.setEnabled(true);
            secretKeyField.setText("");
            secretKeyField.setEditable(true);
            secretKeyField.setEnabled(true);
        });

        JButton savekeyButton = new JButton("Save Key Details");
        savekeyButton.addActionListener(e -> {
            try {
                // Prompt the user to select a save location
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Save Encryption Details");
                fileChooser.setSelectedFile(new File("Text_Encryption_Details.txt"));

                int userSelection = fileChooser.showSaveDialog(null);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File saveFile = fileChooser.getSelectedFile();

                    // Write encryption details to file
                    saveTextEncryptionDetails(saveFile, cipherModeComboBox, paddingComboBox, ivString, keySizeComboBox,
                            key, formatGroup, inputTextArea.getText(), outputTextArea.getText());

                    JOptionPane.showMessageDialog(null, "Text Encryption details saved successfully!", "Success",
                            JOptionPane.INFORMATION_MESSAGE);
                }

            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Error saving encryption details: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        });

        // Progress Bar
        operationProgressBar = new JProgressBar();
        operationProgressBar.setStringPainted(true);
        operationProgressBar.setString("Selecting the Encrypting Parameters.");

        buttonPanel.add(encryptButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(savekeyButton);
        // Main layout
        JPanel contentPanel = new JPanel(new BorderLayout());

        JPanel centerRightPanel = new JPanel(new BorderLayout());
        centerRightPanel.add(centerPanel, BorderLayout.CENTER);
        centerRightPanel.add(rightPanel, BorderLayout.EAST);

        contentPanel.add(centerRightPanel, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(buttonPanel, BorderLayout.NORTH);
        bottomPanel.add(operationProgressBar, BorderLayout.SOUTH);

        contentPanel.add(bottomPanel, BorderLayout.SOUTH);

        return contentPanel;
    }

    public JPanel DecryptionView(File selectedFile) {

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
        fileInfoLabel = new JLabel(
                selectedFile != null ? "Selected file: " + selectedFile.getName() : "No file selected");
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
        outputPanel.setBorder(BorderFactory.createTitledBorder("Decrypted Output"));

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
        rightPanel.setBorder(BorderFactory.createTitledBorder("Decryption Options"));

        // Cipher Mode
        JPanel cipherModePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        cipherModePanel.add(new JLabel("Cipher Mode:"));

        cipherModeComboBox = new JComboBox<>(new String[] { "ECB", "CBC", "CTR", "GCM" });
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

        paddingComboBox = new JComboBox<>(new String[] { "PKCS5Padding", "NoPadding" });
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
        ivTextField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                String ivText = ivTextField.getText().trim(); // Trim whitespace
                System.out.println("Focus Lost Event Triggered"); // Debugging step

                if (ivText.length() != 16) {
                    ivString = ivTextField.getText();
                } else {
                    byte[] temp = ivTextField.getText().getBytes();
                    System.out.println(java.util.Arrays.toString(temp));
                    ivString = Base64.getEncoder().encodeToString(temp);
                }
            }
        });

        JButton ivHelpButton = new JButton("?");
        ivHelpButton.setMargin(new Insets(0, 5, 0, 5));
        ivHelpButton.addActionListener(e -> showHelp("Initialization Vector",
                "IV is required for CBC, CTR, and GCM modes.\n" +
                        "It should be 16 bytes (characters) long and unique for each encryption."));
        ivPanel.add(ivHelpButton);

        // Key Size
        JPanel keySizePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        keySizePanel.add(new JLabel("Key Size:"));

        keySizeComboBox = new JComboBox<>(new String[] { "128", "192", "256" });
        keySizePanel.add(keySizeComboBox);
        JButton keySizeHelpButton = new JButton("?");
        keySizeHelpButton.setMargin(new Insets(0, 5, 0, 5));
        keySizeHelpButton.addActionListener(e -> showHelp("Key Size",
                "Larger keys provide more security but may be slower.\n" +
                        "128 - Standard AES key size (16 chars)\n" +
                        "192 - Increased security (24 chars)\n" +
                        "256 - Maximum security (32 chars)"));
        keySizePanel.add(keySizeHelpButton);

        // Secret Key
        JPanel secretKeyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        secretKeyPanel.add(new JLabel("Secret Key:"));

        secretKeyField = new JPasswordField(16);
        secretKeyPanel.add(secretKeyField);

        keySizeComboBox.addActionListener(e -> {
            int selectedSize = Integer.parseInt((String) keySizeComboBox.getSelectedItem());
            int requiredLength = selectedSize / 8; // 128 -> 16, 192 -> 24, 256 -> 32
            secretKeyField.setColumns(requiredLength);
            secretKeyField.setText(""); // Clear the field when size changes
        });

        // Add Focus Listener to Validate Key Length
        secretKeyField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                int selectedSize = Integer.parseInt((String) keySizeComboBox.getSelectedItem());
                int requiredLength = selectedSize / 8;
                String keyText = new String(secretKeyField.getPassword()).trim();

                if (keyText.length() != requiredLength) {
                    char[] a = secretKeyField.getPassword();
                    String s = String.valueOf(a);
                    key = s;
                } else {
                    char[] a = secretKeyField.getPassword();
                    String s = String.valueOf(a);
                    byte[] t = s.getBytes();
                    key = Base64.getEncoder().encodeToString(t);
                }
            }
        });

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
        base64RadioButton.setActionCommand("Base64");
        hexRadioButton = new JRadioButton("Hex");
        hexRadioButton.setActionCommand("Hex");

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

        JButton encryptButton = new JButton("Decrypt");
        encryptButton.addActionListener(e -> controller.handleActualFileDecrypt(selectedFile, cipherModeComboBox,
                paddingComboBox, ivString, keySizeComboBox, key, formatGroup));

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {
            // inputTextArea.setText("");
            outputTextArea.setText("");
            ivTextField.setText("");
            secretKeyField.setText("");
        });

        JButton showoutButton = new JButton("Show Decrypted Output");
        showoutButton.addActionListener(e -> {
            try {
                String fileName = selectedFile.getName();
                String parentPath = selectedFile.getParent();

                // Match naming logic from decryption service
                String baseName = fileName.replaceFirst("^b64_encrypted_|^hex_encrypted_", "");
                String outputName = baseName.replaceAll("(\\.\\w+)$", "_decrypted$1");
                File decryptedFile = new File(parentPath, outputName);

                // Handle _copy version fallback
                if (!decryptedFile.exists()) {
                    decryptedFile = new File(parentPath, outputName.replace(".", "_copy."));
                }

                if (!decryptedFile.exists()) {
                    JOptionPane.showMessageDialog(null, "No decrypted file found!", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // Read decrypted file content
                StringBuilder decryptedContent = new StringBuilder();
                try (Scanner myReader = new Scanner(decryptedFile)) {
                    while (myReader.hasNextLine()) {
                        decryptedContent.append(myReader.nextLine()).append("\n");
                    }
                }

                // Show content
                outputTextArea.setText(decryptedContent.toString());
                outputTextArea.setEditable(false);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Error reading decrypted file: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
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

    public JPanel TextDecryptionView() {
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
        inputTextArea.setEditable(true);

        // Output panel
        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.setBorder(BorderFactory.createTitledBorder("Decrypted Output"));
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
        rightPanel.setBorder(BorderFactory.createTitledBorder("Decryption Options"));

        // Cipher Mode
        JPanel cipherModePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        cipherModePanel.add(new JLabel("Cipher Mode:"));

        cipherModeComboBox = new JComboBox<>(new String[] { "ECB", "CBC", "CTR", "GCM" });
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

        paddingComboBox = new JComboBox<>(new String[] { "PKCS5Padding", "NoPadding" });
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
        ivTextField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                String ivText = ivTextField.getText().trim(); // Trim whitespace
                System.out.println("Focus Lost Event Triggered"); // Debugging step

                if (ivText.length() != 16) {
                    ivString = ivTextField.getText();
                } else {
                    byte[] temp = ivTextField.getText().getBytes();
                    System.out.println(java.util.Arrays.toString(temp));
                    ivString = Base64.getEncoder().encodeToString(temp);
                }
            }
        });

        JButton ivHelpButton = new JButton("?");
        ivHelpButton.setMargin(new Insets(0, 5, 0, 5));
        ivHelpButton.addActionListener(e -> showHelp("Initialization Vector",
                "IV is required for CBC, CTR, and GCM modes.\n" +
                        "It should be 16 bytes (characters) long and unique for each encryption."));
        ivPanel.add(ivHelpButton);

        // Key Size
        JPanel keySizePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        keySizePanel.add(new JLabel("Key Size:"));

        keySizeComboBox = new JComboBox<>(new String[] { "128", "192", "256" });
        keySizePanel.add(keySizeComboBox);
        JButton keySizeHelpButton = new JButton("?");
        keySizeHelpButton.setMargin(new Insets(0, 5, 0, 5));
        keySizeHelpButton.addActionListener(e -> showHelp("Key Size",
                "Larger keys provide more security but may be slower.\n" +
                        "128 - Standard AES key size (16 chars)\n" +
                        "192 - Increased security (24 chars)\n" +
                        "256 - Maximum security (32 chars)"));
        keySizePanel.add(keySizeHelpButton);

        // Secret Key
        JPanel secretKeyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        secretKeyPanel.add(new JLabel("Secret Key:"));

        secretKeyField = new JPasswordField(16);
        secretKeyPanel.add(secretKeyField);

        keySizeComboBox.addActionListener(e -> {
            int selectedSize = Integer.parseInt((String) keySizeComboBox.getSelectedItem());
            int requiredLength = selectedSize / 8; // 128 -> 16, 192 -> 24, 256 -> 32
            secretKeyField.setColumns(requiredLength);
            secretKeyField.setText(""); // Clear the field when size changes
        });

        // Add Focus Listener to Validate Key Length
        secretKeyField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                int selectedSize = Integer.parseInt((String) keySizeComboBox.getSelectedItem());
                int requiredLength = selectedSize / 8;
                String keyText = new String(secretKeyField.getPassword()).trim();

                if (keyText.length() != requiredLength) {
                    char[] a = secretKeyField.getPassword();
                    String s = String.valueOf(a);
                    key = s;
                } else {
                    char[] a = secretKeyField.getPassword();
                    String s = String.valueOf(a);
                    byte[] t = s.getBytes();
                    key = Base64.getEncoder().encodeToString(t);
                }
            }
        });

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
        base64RadioButton.setActionCommand("Base64");
        hexRadioButton = new JRadioButton("Hex");
        hexRadioButton.setActionCommand("Hex");

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

        JButton decryptButton = new JButton("Decrypt");
        decryptButton.addActionListener(e -> {
            // controller.handleActualFileEncrypt(selectedFile,cipherModeComboBox,paddingComboBox,ivString,keySizeComboBox,key,formatGroup)
            try {
                if (inputTextArea.getText().trim().isEmpty()) {
                    JOptionPane.showMessageDialog(null, "No Text found for Decryption!", "Error",
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }

                String decryptedTextContent = controller.handleActualTextDecrypt(inputTextArea, cipherModeComboBox,
                        paddingComboBox, ivString, keySizeComboBox, key, formatGroup);

                // Display the encrypted content in the text area
                outputTextArea.setText(decryptedTextContent);
                outputTextArea.setEditable(false);

            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Error reading Decrypted file: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        });

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {
            // inputTextArea.setText("");
            // outputTextArea.setText("");
            ivTextField.setText("");
            secretKeyField.setText("");
        });

        // Progress Bar
        operationProgressBar = new JProgressBar();
        operationProgressBar.setStringPainted(true);
        operationProgressBar.setString("Ready");

        buttonPanel.add(decryptButton);
        buttonPanel.add(clearButton);
        // Main layout
        JPanel contentPanel = new JPanel(new BorderLayout());

        JPanel centerRightPanel = new JPanel(new BorderLayout());
        centerRightPanel.add(centerPanel, BorderLayout.CENTER);
        centerRightPanel.add(rightPanel, BorderLayout.EAST);

        contentPanel.add(centerRightPanel, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(buttonPanel, BorderLayout.NORTH);
        bottomPanel.add(operationProgressBar, BorderLayout.SOUTH);

        contentPanel.add(bottomPanel, BorderLayout.SOUTH);

        return contentPanel;
    }

    public JPanel fileContentPanel(File selectedFile){
        JPanel contentPanel = new JPanel(new BorderLayout());
        // contentPanel.add(new JLabel("Selected File: " + selectedFile.getAbsolutePath()));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel centerPanel = new JPanel(new BorderLayout());

        // --- Input Panel ---
        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.setBorder(BorderFactory.createTitledBorder("Selected File"));

        JTextArea inputArea = new JTextArea(2, 40);
        inputArea.setText(selectedFile.getAbsolutePath());
        inputArea.setLineWrap(true);
        inputArea.setWrapStyleWord(true);
        JScrollPane inputScroll = new JScrollPane(inputArea);
        inputPanel.add(inputScroll, BorderLayout.CENTER);

        // --- Output Panel ---
        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.setBorder(BorderFactory.createTitledBorder("Internal File Content (Readable if .txt)"));

        JTextArea outputArea = new JTextArea(12, 40);
        outputArea.setLineWrap(true);
        outputArea.setWrapStyleWord(true);
        outputArea.setEditable(false);
        JScrollPane outputScroll = new JScrollPane(outputArea);
        outputPanel.add(outputScroll, BorderLayout.CENTER);

        // Add both panels to center
        centerPanel.add(inputPanel,BorderLayout.NORTH);
        centerPanel.add(outputPanel,BorderLayout.CENTER);

        // --- Button Panel ---
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        updateStatus("Your File is Being readed... It may take some time based on your file content/size after clicking on Show");
        JButton readButton = new JButton("Show Content");
        readButton.addActionListener(e -> {
            String content = controller.handleFileRead(selectedFile);
            outputArea.setText(content);
        });

        buttonPanel.add(readButton);
        // Wrap everything in main content panel
        contentPanel.add(centerPanel, BorderLayout.CENTER);
        contentPanel.add(buttonPanel, BorderLayout.SOUTH);

        return contentPanel;
    }

    public JPanel showKeyConvertionView() {
        // Main Panel
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel centerPanel = new JPanel(new GridLayout(2, 1, 0, 10));

        // --- Input Panel ---
        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.setBorder(BorderFactory.createTitledBorder("Plain Text or Base64"));

        JTextArea inputArea = new JTextArea(8, 40);
        inputArea.setLineWrap(true);
        inputArea.setWrapStyleWord(true);
        JScrollPane inputScroll = new JScrollPane(inputArea);
        inputPanel.add(inputScroll, BorderLayout.CENTER);

        // --- Output Panel ---
        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.setBorder(BorderFactory.createTitledBorder("Converted Result"));

        JTextArea outputArea = new JTextArea(8, 40);
        outputArea.setLineWrap(true);
        outputArea.setWrapStyleWord(true);
        outputArea.setEditable(false);
        JScrollPane outputScroll = new JScrollPane(outputArea);
        outputPanel.add(outputScroll, BorderLayout.CENTER);

        // Add both panels to center
        centerPanel.add(inputPanel);
        centerPanel.add(outputPanel);

        // --- Button Panel ---
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        JButton toBase64Button = new JButton("Convert to Base64");
        toBase64Button.addActionListener(e -> {
            try {
                String plainText = inputArea.getText().trim();
                if (plainText.isEmpty()) {
                    JOptionPane.showMessageDialog(null, "Input is empty!");
                    return;
                }
                byte[] temp = plainText.getBytes();
                System.out.println(java.util.Arrays.toString(temp));
                String base64 = Base64.getEncoder().encodeToString(temp);
                // String base64 =
                // Base64.getEncoder().encodeToString(plainText.getBytes(StandardCharsets.UTF_8));
                outputArea.setText(base64);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Conversion to Base64 failed: " + ex.getMessage());
            }
        });

        JButton toPlainTextButton = new JButton("Convert to Text");
        toPlainTextButton.addActionListener(e -> {
            try {
                String base64Input = inputArea.getText().trim();
                if (base64Input.isEmpty()) {
                    JOptionPane.showMessageDialog(null, "Input is empty!");
                    return;
                }
                byte[] decodedBytes = Base64.getDecoder().decode(base64Input);
                String plainText = new String(decodedBytes);
                outputArea.setText(plainText);
            } catch (IllegalArgumentException ex) {
                JOptionPane.showMessageDialog(null, "Invalid Base64 input: " + ex.getMessage());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Conversion to Text failed: " + ex.getMessage());
            }
        });

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {
            inputArea.setText("");
            outputArea.setText("");
        });

        buttonPanel.add(toBase64Button);
        buttonPanel.add(toPlainTextButton);
        buttonPanel.add(clearButton);
        // Wrap everything in main content panel
        contentPanel.add(centerPanel, BorderLayout.CENTER);
        contentPanel.add(buttonPanel, BorderLayout.SOUTH);

        return contentPanel;
    }

    private void saveEncryptionDetails(File file, JComboBox<String> cipherModeComboBox,
            JComboBox<String> paddingComboBox, String ivString, JComboBox<String> keySizeComboBox, String key,
            ButtonGroup formatGroup) throws IOException {
        StringBuilder details = new StringBuilder();
        details.append("Encryption Details\n");
        details.append("==================\n");
        details.append("Algorithm: ").append("AES/").append("\n");
        details.append("Cipher Mode: ").append(cipherModeComboBox.getSelectedItem().toString()).append("\n");
        details.append("Padding: ").append(paddingComboBox.getSelectedItem().toString()).append("\n");
        if (ivString != null) {
            details.append("IV (Base64): ").append(ivString).append("\n");
        } else {
            details.append("IV: Not used (ECB Mode)\n");
        }
        details.append("Key Size : ").append(Integer.parseInt(keySizeComboBox.getSelectedItem().toString()))
                .append("\n");
        details.append("Key : ").append(key).append("\n");
        String selectedFormat = getSelectedButtonText(formatGroup);
        details.append("Format Group (Base64)/Hex: ").append(selectedFormat).append("\n");

        Files.write(file.toPath(), details.toString().getBytes(StandardCharsets.UTF_8));
    }

    private void saveTextEncryptionDetails(File file, JComboBox<String> cipherModeComboBox,
            JComboBox<String> paddingComboBox, String ivString, JComboBox<String> keySizeComboBox, String key,
            ButtonGroup formatGroup, String input, String output) throws IOException {
        StringBuilder details = new StringBuilder();
        details.append("Text Encryption Details\n");
        details.append("==================\n");
        details.append("Input Text : ").append(input).append("\n");
        details.append("Algorithm: ").append("AES/").append("\n");
        details.append("Cipher Mode: ").append(cipherModeComboBox.getSelectedItem().toString()).append("\n");
        details.append("Padding: ").append(paddingComboBox.getSelectedItem().toString()).append("\n");
        if (ivString != null) {
            details.append("IV (Base64): ").append(ivString).append("\n");
        } else {
            details.append("IV: Not used (ECB Mode)\n");
        }
        details.append("Key Size : ").append(Integer.parseInt(keySizeComboBox.getSelectedItem().toString()))
                .append("\n");
        details.append("Key : ").append(key).append("\n");
        String selectedFormat = getSelectedButtonText(formatGroup);
        details.append("Format Group (Base64)/Hex: ").append(selectedFormat).append("\n");
        details.append("Encrypted Output : ").append(output).append("\n");
        Files.write(file.toPath(), details.toString().getBytes(StandardCharsets.UTF_8));
    }

    private String getSelectedButtonText(ButtonGroup buttonGroup) {
        for (Enumeration<AbstractButton> buttons = buttonGroup.getElements(); buttons.hasMoreElements();) {
            AbstractButton button = buttons.nextElement();
            if (button.isSelected()) {
                return button.getText(); // Return the selected radio button's text
            }
        }
        return "Unknown"; // Default if no button is selected (shouldn't happen)
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
        progressBar.setValue(0);
    }

    public void updateStatusLive(int progressPercentage){
        progressBar.setValue(progressPercentage);
        progressBar.setString("Your File is being readed : "+progressPercentage + "% completed");
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