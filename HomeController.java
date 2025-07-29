package com.tech_titans.controller;

import com.tech_titans.service.EncryptionService;
import com.tech_titans.service.FileTransferService;
import com.tech_titans.view.HomeView;
import com.tech_titans.model.EncryptionModel;

import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;
import javax.swing.text.StyledDocument;

import javax.swing.text.Style;

import java.awt.*;

public class HomeController {
    private HomeView homeView;
    private File selectedFile;
    private FileTransferService fileTransferService;
    
    public HomeController(HomeView homeView) {
        this.homeView = homeView;
        this.fileTransferService = new FileTransferService();

    }

    public void handleHome(ActionEvent e) {
        JPanel homPanel = homeView.mainHomeFrame();
        homeView.setMainPanelContent(homPanel);
        homeView.updateStatus("Home");
    }

    // Handle "Send File" menu item click
    public void handleSendFile(ActionEvent e) {
        JPanel sendFilePanel = homeView.createSendFilePanel();
        homeView.setMainPanelContent(sendFilePanel);
        homeView.updateStatus("Ready to send file");
    }

    // Handle "Receive File" menu item click
    public void handleReceiveFile(ActionEvent e) {
        JPanel receiveFilePanel = homeView.createReceiveFilePanel();
        homeView.setMainPanelContent(receiveFilePanel);
        homeView.updateStatus("Ready to receive files");
    }

    // Handle file selection for sending
    public void handleSelectFileToSend(JTextField filePathField) {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(homeView);

        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            filePathField.setText(selectedFile.getAbsolutePath());
        }
    }

    // Handle save location selection for receiving
    public void handleSelectSaveLocation(JTextField savePathField) {
        JFileChooser dirChooser = new JFileChooser();
        dirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int result = dirChooser.showOpenDialog(homeView);

        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedDir = dirChooser.getSelectedFile();
            savePathField.setText(selectedDir.getAbsolutePath());
        }
    }

    // Handle the actual file sending
    public void handleSendFile(String filePath, String ipAddress, int port,
            JProgressBar progressBar, JTextArea statusArea) {
        if (filePath == null || filePath.isEmpty()) {
            JOptionPane.showMessageDialog(homeView, "Please select a file to send.",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        File fileToSend = new File(filePath);
        if (!fileToSend.exists()) {
            JOptionPane.showMessageDialog(homeView, "Selected file does not exist.",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        statusArea.append("Starting file transfer to " + ipAddress + ":" + port + "\n");
        progressBar.setValue(0);
        progressBar.setString("Connecting...");

        try {
            // last parameter is the whole function..
            fileTransferService.sendFile(fileToSend, ipAddress, port, new FileTransferService.ProgressCallback() {
                @Override
                public void onProgressUpdate(int progressPercentage) {
                    SwingUtilities.invokeLater(() -> {
                        progressBar.setValue(progressPercentage);
                        progressBar.setString(progressPercentage + "%");
                    });
                }

                @Override
                public void onTransferComplete(String fileName) {
                    SwingUtilities.invokeLater(() -> {
                        statusArea.append("File transfer completed: " + fileName + "\n");
                        progressBar.setValue(100);
                        progressBar.setString("Transfer complete");
                        homeView.updateStatus("File sent successfully");
                    });
                }

                @Override
                public void onFileReceived(String filePath) {
                    // Not used for sending
                }

                @Override
                public void onServerStarted(int port) {
                    // Not used for sending
                }

                @Override
                public void onTransferError(String errorMessage) {
                    SwingUtilities.invokeLater(() -> {
                        statusArea.append("ERROR: " + errorMessage + "\n");
                        progressBar.setString("Transfer failed");
                        homeView.updateStatus("File transfer failed");
                    });
                }
            });
        } catch (IOException e) {
            statusArea.append("ERROR: " + e.getMessage() + "\n");
            progressBar.setString("Transfer failed");
        }
    }

    // Start the server to receive files
    public void handleStartReceiveServer(String saveDir, JProgressBar progressBar, JTextArea statusArea) {
        if (saveDir == null || saveDir.isEmpty()) {
            JOptionPane.showMessageDialog(homeView, "Please select a save location.",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        File saveDirFile = new File(saveDir);
        if (!saveDirFile.exists() || !saveDirFile.isDirectory()) {
            if (!saveDirFile.mkdirs()) {
                JOptionPane.showMessageDialog(homeView, "Could not create the save directory.",
                        "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
        }

        try {
            fileTransferService.startReceiveServer(saveDir, new FileTransferService.ProgressCallback() {
                @Override
                public void onProgressUpdate(int progressPercentage) {
                    SwingUtilities.invokeLater(() -> {
                        progressBar.setValue(progressPercentage);
                        progressBar.setString("Receiving: " + progressPercentage + "%");
                    });
                }

                @Override
                public void onTransferComplete(String fileName) {
                    // Not used for receiving
                }

                @Override
                public void onFileReceived(String filePath) {
                    SwingUtilities.invokeLater(() -> {
                        statusArea.append("File received: " + filePath + "\n");
                        progressBar.setValue(0);
                        progressBar.setString("Ready for next file");
                    });
                }

                @Override
                public void onServerStarted(int port) {
                    SwingUtilities.invokeLater(() -> {
                        statusArea.append("Server started on port " + port + "\n");
                        statusArea.append("Waiting for incoming files...\n");
                        progressBar.setString("Server running");
                        homeView.updateStatus("Receiving server running");
                    });
                }

                @Override
                public void onTransferError(String errorMessage) {
                    SwingUtilities.invokeLater(() -> {
                        statusArea.append("ERROR: " + errorMessage + "\n");
                    });
                }
            });
        } catch (IOException e) {
            statusArea.append("ERROR: Could not start server: " + e.getMessage() + "\n");
            progressBar.setString("Server failed to start");
        }
    }

    // Stop the receiving server
    public void handleStopReceiveServer(JTextArea statusArea) {
        fileTransferService.stopReceiveServer();
        statusArea.append("Server stopped\n");
        homeView.updateStatus("Receive server stopped");
    }

    public void handleFileEncrypt(ActionEvent e) {
        
        if (selectedFile == null) {
            homeView.showMessage("Please select/open a file first from file menu!");
            return;
        } else {
            JPanel EncPanel = homeView.EncryptionView(selectedFile);

            homeView.setMainPanelContent(EncPanel);
        }
        homeView.updateStatus("Encrypting: " + selectedFile.getName());
    }

    public void handleFileDecrypt(ActionEvent e) {
        
        String fileName = "";
        if (selectedFile == null) {
            homeView.showMessage("Please select/open a file first from file menu!");
            return;
        }

        if (selectedFile != null) {
            fileName = selectedFile.getName().toLowerCase();
        }

        if (!(fileName.startsWith("b64_encrypted_") || fileName.startsWith("hex_encrypted_"))) {
            homeView.showMessage(
                    "Selected file is not a valid encrypted file (must start with 'b64_encrypted_' or 'hex_encrypted_')!");
            return;
        } else {
            JPanel DencPanel = homeView.DecryptionView(selectedFile);
            homeView.setMainPanelContent(DencPanel);
        }
        homeView.updateStatus("Decrypting: " + selectedFile.getName());
    }

    public void handleActualFileEncrypt(File selectedFile, JComboBox<String> cipherModeComboBox,
            JComboBox<String> paddingComboBox, String ivString, JComboBox<String> keySizeComboBox, String key,
            ButtonGroup formatGroup) {
        byte[] decodedData = Base64.getDecoder().decode(ivString);
        String outputFormat = formatGroup.getSelection().getActionCommand();
        EncryptionModel actualFile = new EncryptionModel(selectedFile.getPath(), key,
                cipherModeComboBox.getSelectedItem().toString(), paddingComboBox.getSelectedItem().toString(),
                Integer.parseInt(keySizeComboBox.getSelectedItem().toString()), outputFormat,
                decodedData);
        boolean done = false;
        if (actualFile != null) {
            homeView.updateStatus("File Object Has been Created");
        }
        try {
            done = EncryptionService.encryptFile(actualFile);
        } catch (Exception e) {
            homeView.updateStatus(e.toString() + "handle Actual");
        }
        if (done == true) {
            homeView.updateStatus("Your File has been Encrypted.");
        }
    }

    public void handleActualFileDecrypt(File selectedFile, JComboBox<String> cipherModeComboBox,
            JComboBox<String> paddingComboBox, String ivString, JComboBox<String> keySizeComboBox, String key,
            ButtonGroup formatGroup) {

        String outputFormat = formatGroup.getSelection().getActionCommand();

        byte[] decodedData;

        try {
            if (outputFormat.equalsIgnoreCase("Base64")) {
                decodedData = Base64.getDecoder().decode(ivString);
            } else {
                decodedData = EncryptionService.hexToBytes(ivString);
            }
        } catch (Exception ex) {
            homeView.showMessage("Invalid IV: Make sure it matches the expected format (" + outputFormat + ").");
            return;
        }

        EncryptionModel actualFile = new EncryptionModel(selectedFile.getPath(), key,
                cipherModeComboBox.getSelectedItem().toString(), paddingComboBox.getSelectedItem().toString(),
                Integer.parseInt(keySizeComboBox.getSelectedItem().toString()), outputFormat,
                decodedData);
        boolean done = false;
        if (actualFile != null) {
            homeView.updateStatus("File Object Has been Created");
        }
        try {
            done = EncryptionService.decryptFile(actualFile);
        } catch (Exception e) {
            homeView.updateStatus(e.toString() + "handle Actual");
        }
        if (done == true) {
            homeView.updateStatus("✅ Your File has been Decrypted.");
            homeView.showMessage("Decryption completed successfully.");
        }
    }

    public void handleTextEncrypt(ActionEvent e) {
        JPanel EncTextPanel = homeView.TextEncryptionView();
        homeView.setMainPanelContent(EncTextPanel);
        homeView.updateStatus("Encrypting: Manual Text");
    }

    public void handleTextDecrypt(ActionEvent e) {
        JPanel EncTextPanel = homeView.TextDecryptionView();
        homeView.setMainPanelContent(EncTextPanel);
        homeView.updateStatus("Decrypting: Manual Text");
    }

    public String handleActualTextEncrypt(JTextArea inputTextArea, JComboBox<String> cipherModeComboBox,
            JComboBox<String> paddingComboBox,
            String ivString, JComboBox<String> keySizeComboBox, String key, ButtonGroup formatGroup) {
        byte[] decodedData = Base64.getDecoder().decode(ivString);
        String outputFormat = formatGroup.getSelection().getActionCommand();
        EncryptionModel actualText = new EncryptionModel(inputTextArea.getText(), key,
                cipherModeComboBox.getSelectedItem().toString(), paddingComboBox.getSelectedItem().toString(),
                decodedData, Integer.parseInt(keySizeComboBox.getSelectedItem().toString()),
                outputFormat);
        String done = "";
        if (actualText != null) {
            homeView.updateStatus("Text Object Has been Created");
        }
        try {
            done = EncryptionService.encryptText(actualText);
        } catch (Exception e) {
            homeView.updateStatus(e.toString() + " while handle Actual Text");
        }
        if (done != null) {
            homeView.updateStatus("Your Text has been encrypted.");
        }
        return done;
    }

    public String handleActualTextDecrypt(JTextArea inputTextArea, JComboBox<String> cipherModeComboBox,
            JComboBox<String> paddingComboBox,
            String ivString, JComboBox<String> keySizeComboBox, String key, ButtonGroup formatGroup) {
        byte[] decodedData = Base64.getDecoder().decode(ivString);
        String outputFormat = formatGroup.getSelection().getActionCommand();
        EncryptionModel actualText = new EncryptionModel(inputTextArea.getText(), key,
                cipherModeComboBox.getSelectedItem().toString(), paddingComboBox.getSelectedItem().toString(),
                decodedData,
                Integer.parseInt(keySizeComboBox.getSelectedItem().toString()), outputFormat);
        String done = "";
        if (actualText != null) {
            homeView.updateStatus("Text Object Has been Created");
        }
        try {
            done = EncryptionService.decryptText(actualText);
        } catch (Exception e) {
            homeView.updateStatus(e.toString() + " while handle Actual Text");
        }
        if (!done.isEmpty()) {
            homeView.updateStatus("Your Text has been decrypted.");
        }
        return done;
    }

    public String handleFileRead(File selectedFile){
        StringBuilder text = new StringBuilder();
        
        if (selectedFile != null) {
            int byteData;
            try (FileInputStream fis = new FileInputStream(selectedFile)) {
                while ((byteData = fis.read()) != -1) {
                    text.append((char) byteData);
                }
            }catch(Exception e){
                homeView.updateStatus(e.getMessage());
            }
        }
        homeView.updateStatus("File Reading is Completed");
        return text.toString();
    }

    public void handleSettings(ActionEvent e) {
        homeView.updateStatus("Opening Settings...");
        JPanel settingsPanel = new JPanel();
        settingsPanel.add(new JLabel("Settings Panel - Work in Progress"));
        homeView.setMainPanelContent(settingsPanel);
    }

    public void handleOpenFile(ActionEvent e) {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            selectedFile = fileChooser.getSelectedFile();
            homeView.updateStatus("Selected File: " + selectedFile.getName());
            showFileSelectionPanel();
        }
    }

    public void handleKeyConvertions(ActionEvent e) {
        JPanel keyConvertionPanel = homeView.showKeyConvertionView();
        homeView.setMainPanelContent(keyConvertionPanel);
        homeView.updateStatus("Converting Base64/Hex <-> Normal");
    }

    private void showFileSelectionPanel() {
        JPanel panel = homeView.fileContentPanel(selectedFile);
        homeView.setMainPanelContent(panel);
    }

    public void handleHelp(ActionEvent e) {
        homeView.updateStatus("Viewing Help Documentation...");

        // Create Help Panel
        JPanel helpPanel = new JPanel();
        helpPanel.setLayout(new BorderLayout());
        helpPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        // Create tabbed pane for better organization
        JTabbedPane tabbedPane = new JTabbedPane();

        // Introduction Tab
        tabbedPane.addTab("Introduction", createIntroductionPanel());

        // File Encryption Tab
        tabbedPane.addTab("File Encryption", createFileEncryptionPanel());

        // File Decryption Tab
        tabbedPane.addTab("File Decryption", createFileDecryptionPanel());

        // Text Encryption Tab
        tabbedPane.addTab("Text Encryption", createTextEncryptionPanel());

        // Text Decryption Tab
        tabbedPane.addTab("Text Decryption", createTextDecryptionPanel());

        // File Transfer Tab
        tabbedPane.addTab("File Transfer", createFileTransferPanel());

        // Technical Info
        tabbedPane.addTab("Technical Info", createTechnicalInfoPanel());

        // FAQ Tab
        tabbedPane.addTab("FAQ", createFAQPanel());

        // Add the tabbed pane to the help panel
        helpPanel.add(tabbedPane, BorderLayout.CENTER);

        // Set the panel content in the main window
        homeView.setMainPanelContent(helpPanel);
    }

    private JPanel createIntroductionPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JTextPane textPane = createStyledTextPane();
        textPane.setText(getIntroductionText());

        JScrollPane scrollPane = new JScrollPane(textPane);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createFileEncryptionPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JTextPane textPane = createStyledTextPane();
        textPane.setText(getFileEncryptionText());

        JScrollPane scrollPane = new JScrollPane(textPane);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createFileDecryptionPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JTextPane textPane = createStyledTextPane();
        textPane.setText(getFileDecryptionText());

        JScrollPane scrollPane = new JScrollPane(textPane);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createTextEncryptionPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JTextPane textPane = createStyledTextPane();
        textPane.setText(getTextEncryptionText());

        JScrollPane scrollPane = new JScrollPane(textPane);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createTextDecryptionPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JTextPane textPane = createStyledTextPane();
        textPane.setText(getTextDecryptionText());

        JScrollPane scrollPane = new JScrollPane(textPane);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createFileTransferPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JTextPane textPane = createStyledTextPane();
        textPane.setText(getFileTransferText());

        JScrollPane scrollPane = new JScrollPane(textPane);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createTechnicalInfoPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JTextPane textPane = createStyledTextPane();
        textPane.setText(getTechnicalInfoText());

        JScrollPane scrollPane = new JScrollPane(textPane);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createFAQPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JTextPane textPane = createStyledTextPane();
        textPane.setText(getFAQText());

        JScrollPane scrollPane = new JScrollPane(textPane);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JTextPane createStyledTextPane() {
        JTextPane textPane = new JTextPane();
        textPane.setEditable(false);

        // Set styles for the text pane
        StyledDocument doc = textPane.getStyledDocument();
        Style defaultStyle = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE);

        Style regular = doc.addStyle("regular", defaultStyle);
        StyleConstants.setFontFamily(regular, "Arial");
        StyleConstants.setFontSize(regular, 14);

        Style heading1 = doc.addStyle("heading1", regular);
        StyleConstants.setFontSize(heading1, 20);
        StyleConstants.setBold(heading1, true);
        StyleConstants.setForeground(heading1, new Color(0, 102, 204));

        Style heading2 = doc.addStyle("heading2", regular);
        StyleConstants.setFontSize(heading2, 16);
        StyleConstants.setBold(heading2, true);
        StyleConstants.setForeground(heading2, new Color(0, 102, 153));

        Style bold = doc.addStyle("bold", regular);
        StyleConstants.setBold(bold, true);

        Style italic = doc.addStyle("italic", regular);
        StyleConstants.setItalic(italic, true);

        Style note = doc.addStyle("note", regular);
        StyleConstants.setBackground(note, new Color(255, 255, 204));
        StyleConstants.setFontSize(note, 14);
        StyleConstants.setItalic(note, true);

        return textPane;
    }

    private String getIntroductionText() {
        return "Welcome to File Encryption & Decryption\n\n" +
                "This application provides powerful yet easy-to-use tools for securing your files and text through advanced encryption techniques. With our application, you can:\n\n"
                +
                "• Encrypt and decrypt files using industry-standard AES encryption\n" +
                "• Encrypt and decrypt text messages\n" +
                "• Securely transfer encrypted files over TCP/IP networks\n" +
                "• Choose from multiple encryption modes and key strengths\n\n" +
                "Whether you're protecting sensitive documents, securing communications, or safely transferring files, our application provides the security tools you need with an intuitive interface.\n\n"
                +
                "Navigate through the help tabs to learn how to use each feature of the application.\n\n" +
                "IMPORTANT: Always remember your encryption keys and settings. If you lose this information, your encrypted data cannot be recovered.";
    }

    private String getFileEncryptionText() {
        return "File Encryption Guide\n\n" +
                "File encryption converts your regular files into securely encrypted versions that can only be read with the correct decryption key.\n\n"
                +
                "Step-by-Step Instructions:\n\n" +
                "1. Select 'File' from the main menu and click 'Open File'\n" +
                "2. Navigate to and select the file you wish to encrypt\n" +
                "3. Select 'Encryption' from the main menu\n" +
                "4. Click 'Encrypt File' option\n" +
                "5. Configure your encryption settings:\n" +
                "   • Encryption Mode: Select from ECB, CBC, CTR, or GCM\n" +
                "   • Padding Method: Choose PKCS5Padding or No Padding\n" +
                "   • IV (Initialization Vector): For CBC, CTR, and GCM modes, either enter a custom IV or click 'Generate IV'\n"
                +
                "   • Key Size: Select 128-bit (16 chars), 192-bit (24 chars), or 256-bit (32 chars)\n" +
                "   • Secret Key: Enter your own key or click 'Generate Key'\n" +
                "   • Output Format: Choose Base64 or Hex encoding\n" +
                "6. Click the 'Encrypt' button\n" +
                "7. Select a location to save your encrypted file\n\n" +
                "IMPORTANT: Save your encryption configuration details (mode, padding, IV, key size, secret key, and format) in a secure location. You will need this exact information to decrypt your file later.";
    }

    private String getFileDecryptionText() {
        return "File Decryption Guide\n\n" +
                "File decryption restores your encrypted files back to their original format using the correct decryption key and settings.\n\n"
                +
                "Step-by-Step Instructions:\n\n" +
                "1. Select 'File' from the main menu and click 'Open File'\n" +
                "2. Navigate to and select the encrypted file you wish to decrypt\n" +
                "3. Select 'Decryption' from the main menu\n" +
                "4. Click 'Decrypt File' option\n" +
                "5. Enter the EXACT same encryption settings that were used when encrypting the file:\n" +
                "   • Decryption Mode: Select the same mode used for encryption (ECB, CBC, CTR, or GCM)\n" +
                "   • Padding Method: Select the same padding used for encryption\n" +
                "   • IV: Enter the same IV used during encryption (for CBC, CTR, and GCM modes)\n" +
                "   • Key Size: Select the same key size used during encryption\n" +
                "   • Secret Key: Enter the exact same secret key used during encryption\n" +
                "   • Input Format: Select the same format used during encryption (Base64 or Hex)\n" +
                "6. Click the 'Decrypt' button\n" +
                "7. Select a location to save your decrypted file\n\n" +
                "IMPORTANT: If any of the decryption settings don't match those used during encryption, the decryption process will fail or produce corrupted output.";
    }

    private String getTextEncryptionText() {
        return "Text Encryption Guide\n\n" +
                "Text encryption allows you to convert plain readable text into encrypted text that can only be read with the correct decryption key.\n\n"
                +
                "Step-by-Step Instructions:\n\n" +
                "1. Select 'Encryption' from the main menu\n" +
                "2. Click 'Encrypt Text' option\n" +
                "3. Type or paste the text you wish to encrypt into the input field\n" +
                "4. Configure your encryption settings:\n" +
                "   • Encryption Mode: Select from ECB, CBC, CTR, or GCM\n" +
                "   • Padding Method: Choose PKCS5Padding or No Padding\n" +
                "   • IV (Initialization Vector): For CBC, CTR, and GCM modes, either enter a custom IV or click 'Generate IV'\n"
                +
                "   • Key Size: Select 128-bit (16 chars), 192-bit (24 chars), or 256-bit (32 chars)\n" +
                "   • Secret Key: Enter your own key or click 'Generate Key'\n" +
                "   • Output Format: Choose Base64 or Hex encoding\n" +
                "5. Click the 'Encrypt' button\n" +
                "6. The encrypted text will appear in the output area\n" +
                "7. You can copy this text to your clipboard or save it to a file\n\n" +
                "IMPORTANT: Save your encryption configuration details (mode, padding, IV, key size, secret key, and format) in a secure location. You will need this exact information to decrypt your text later.";
    }

    private String getTextDecryptionText() {
        return "Text Decryption Guide\n\n" +
                "Text decryption restores your encrypted text back to readable format using the correct decryption key and settings.\n\n"
                +
                "Step-by-Step Instructions:\n\n" +
                "1. Select 'Decryption' from the main menu\n" +
                "2. Click 'Decrypt Text' option\n" +
                "3. Paste the encrypted text into the input field\n" +
                "4. Enter the EXACT same encryption settings that were used when encrypting the text:\n" +
                "   • Decryption Mode: Select the same mode used for encryption (ECB, CBC, CTR, or GCM)\n" +
                "   • Padding Method: Select the same padding used for encryption\n" +
                "   • IV: Enter the same IV used during encryption (for CBC, CTR, and GCM modes)\n" +
                "   • Key Size: Select the same key size used during encryption\n" +
                "   • Secret Key: Enter the exact same secret key used during encryption\n" +
                "   • Input Format: Select the same format used during encryption (Base64 or Hex)\n" +
                "5. Click the 'Decrypt' button\n" +
                "6. The decrypted text will appear in the output area\n\n" +
                "IMPORTANT: If any of the decryption settings don't match those used during encryption, the decryption process will fail or produce corrupted output.";
    }

    private String getFileTransferText() {
        return "Secure File Transfer Guide\n\n" +
                "The Secure File Transfer feature allows you to send and receive encrypted files directly between devices over TCP/IP networks.\n\n"
                +
                "Sending Files:\n\n" +
                "1. Select 'Transfer' from the main menu and click 'Send File'\n" +
                "2. In the Send File panel:\n" +
                "   • Click 'Browse' to select the file you wish to send\n" +
                "   • Enter the receiver's IP address (IPv4 or IPv6)\n" +
                "   • Verify the port number (default is 9999)\n" +
               
                "   • Click 'Start Sending' to begin the transfer\n" +
                "3. The progress bar will show the transfer status\n" +
                "4. Once complete, a confirmation message will appear\n\n" +
                "Receiving Files:\n\n" +
                "1. Select 'Transfer' from the main menu and click 'Receive File'\n" +
                "2. In the Receive File panel:\n" +
                "   • Verify or change the save location for incoming files\n" +
                "   • Note your IP addresses displayed in the panel - you will need to share your IPv4 or IPv6 address with the sender\n"
                +
                "   • For IPv6 connectivity, use the temporary IPv6 address shown\n" +
                "   • Verify the port number (default is 9999)\n" +
                "   • Click 'Start Receiving' to begin listening for incoming files\n" +
                "3. The status area will show when a connection is established\n" +
                "4. The progress bar will show the download status\n" +
                "5. Once complete, the file will be saved to your specified location\n" +
                "6. Click 'Stop Receiving' when you're done receiving files\n\n" +
                "IPv6 Connectivity:\n\n" +
                "The application supports both IPv4 and IPv6 addresses for file transfers. When receiving files, your temporary IPv6 address is displayed to allow connectivity across various network configurations. Using IPv6 can help bypass certain network restrictions and enable direct device-to-device connections.\n\n"
                +
                "IMPORTANT: For successful file transfers, ensure that:\n" +
                "• Both devices are connected to the same network or can reach each other over the internet\n" +
                "• Any necessary firewall exceptions are configured for the port being used\n" +
                "• The receiver has started listening before the sender attempts to connect";
    }

    private String getTechnicalInfoText() {
        return "Technical Information\n\n" +
                "Encryption Standards:\n\n" +
                "This application uses the Advanced Encryption Standard (AES) algorithm, which is a symmetric block cipher adopted worldwide as a secure encryption standard. AES operates on fixed block sizes of 128 bits and supports key lengths of 128, 192, and 256 bits.\n\n"
                +
                "Encryption Modes:\n\n" +
                "• ECB (Electronic Codebook):\n" +
                "  - Simplest encryption mode where each block is encrypted independently\n" +
                "  - Does not require an IV (Initialization Vector)\n" +
                "  - Less secure for data with patterns, not recommended for large files\n\n" +
                "• CBC (Cipher Block Chaining):\n" +
                "  - Each block of plaintext is XORed with the previous ciphertext block before encryption\n" +
                "  - Requires an IV for the first block\n" +
                "  - More secure than ECB as patterns in the data are obscured\n\n" +
                "• CTR (Counter):\n" +
                "  - Converts block cipher into stream cipher by encrypting incremental counter values\n" +
                "  - Requires an IV (nonce) combined with counter\n" +
                "  - Allows parallel encryption/decryption and random access to encrypted data\n\n" +
                "• GCM (Galois/Counter Mode):\n" +
                "  - Provides both encryption and authentication\n" +
                "  - Requires an IV\n" +
                "  - Detects tampering of the ciphertext\n\n" +
                "Padding Methods:\n\n" +
                "• PKCS5Padding:\n" +
                "  - Adds bytes to ensure the data fits the block size\n" +
                "  - The value of each padding byte is the number of bytes added\n\n" +
                "• No Padding:\n" +
                "  - Requires data to be exact multiple of block size\n" +
                "  - Only works with certain modes (CTR and GCM)\n\n" +
                "Key Sizes:\n\n" +
                "• 128-bit (16 characters): Standard security level\n" +
                "• 192-bit (24 characters): Enhanced security level\n" +
                "• 256-bit (32 characters): Maximum security level\n\n" +
                "Output Formats:\n\n" +
                "• Base64: Encodes binary data as ASCII text using 64 printable characters\n" +
                "• Hex: Represents each byte as two hexadecimal characters\n\n" +
                "Network Transfer Protocol:\n\n" +
                "The file transfer feature uses TCP/IP socket connections which provide reliable, ordered delivery of data between devices. The application supports both IPv4 and IPv6 addressing to ensure compatibility across different network configurations.";
    }

    private String getFAQText() {
        return "Frequently Asked Questions\n\n" +
                "Q: Why is my decrypted file corrupted or unreadable?\n" +
                "A: Decryption will fail if any of the settings (mode, padding, IV, key, format) don't exactly match those used during encryption. Double-check all settings and ensure you're using the correct encrypted file.\n\n"
                +
                "Q: What happens if I lose my encryption key?\n" +
                "A: There is no way to recover encrypted data without the correct key. AES encryption is designed to be mathematically impossible to break without the key. Always store your keys securely.\n\n"
                +
                "Q: Which encryption mode should I use?\n" +
                "A: For most purposes, CBC or GCM modes are recommended. CBC provides good security for general use, while GCM adds authentication to detect tampering. Avoid ECB mode for anything but very small amounts of data.\n\n"
                +
                "Q: What key size should I choose?\n" +
                "A: 256-bit keys provide the highest security level and are recommended for sensitive data. 128-bit keys are still considered secure and offer faster processing.\n\n"
                +
                "Q: Can I send files to devices on different networks?\n" +
                "A: Yes, if the receiving device is accessible from the internet. This typically requires port forwarding on the receiver's router or using IPv6 addressing. Using the temporary IPv6 address can help establish direct connections across networks.\n\n"
                +
                "Q: The file transfer isn't working. What could be wrong?\n" +
                "A: Common issues include:\n" +
                "  • Incorrect IP address\n" +
                "  • Firewall blocking the connection\n" +
                "  • Receiver not listening before sender initiates\n" +
                "  • Network restrictions preventing direct connections\n" +
                "Try using the IPv6 address instead of IPv4, ensure firewalls allow the application, and verify the receiver is actively listening.\n\n"
                +
                "Q: Is my data secure during file transfers?\n" +
                "A: Yes, files are encrypted before transfer using the AES algorithm with your chosen settings. The encrypted data cannot be read without the correct decryption key and settings.\n\n"
                +
                "Q: Why does the application show my temporary IPv6 address?\n" +
                "A: Temporary IPv6 addresses enhance privacy while enabling direct connections across different network configurations. Using IPv6 can help bypass certain network restrictions that might prevent IPv4 connections.\n\n"
                +
                "Q: How can I verify my encryption is working correctly?\n" +
                "A: Encrypt a simple test file, then decrypt it with the same settings and compare it to the original. They should be identical. For text, encrypt a sample message and verify you can decrypt it back to the original text.";
    }

    public void handleHelp2(ActionEvent e) {
        homeView.updateStatus("Encryption/Decryption Simulation Help...");

        // Create Help Panel
        JPanel helpPanel = new JPanel();
        helpPanel.setLayout(new BorderLayout());

        // Create a Text Area to Display Help Information
        JTextArea helpText = new JTextArea();
        helpText.setEditable(false);
        helpText.setLineWrap(true);
        helpText.setWrapStyleWord(true);

        helpText.setText(
                "HELP SECTION - Encryption & Decryption Guide\n\n"
                        + "Introduction:\n"
                        + "This application helps you securely encrypt and decrypt files and text using AES encryption.\n\n"

                        + "How to Encrypt a File:\n"
                        + "1. Select File Menu.\n"
                        + "2. Click 'Open File' and choose a file.\n"
                        + "3. Select Encryption menu.\n"
                        + "4. To Encrypted File select Encrypt File Option.\n"
                        + "5. Select Encryption Cipher mode (ECB,CBC,CTR,GCM).\n"
                        + "6. Select Encryption Padding (PKCS5Padding , No Padding).\n"
                        + "7. Enter IV For Cipher mode CBC,CTR and GCM Or Generate IV.\n"
                        + "8. Select Secret Key Size (128->16,192->24,256->32).\n"
                        + "9. Enter Secret Key Or Generate Secret key.\n"
                        + "10. Select Output Format (Base64 , Hex).\n"
                        + "11. Click On Encrypt Button File will be Encrypted and Stored.\n"
                        + "12. Save Key details for Decryption.\n\n"

                        + "How to Decrypt a File:\n"
                        + "1. Select File Menu.\n"
                        + "2. Click 'Open File' and choose an encrypted file.\n"
                        + "3. Select Decryption menu.\n"
                        + "4. To Decrypted File select Decrypt File Option.\n"
                        + "5. Select Decryption Cipher mode (ECB,CBC,CTR,GCM).\n"
                        + "6. Select Decryption Padding (PKCS5Padding , No Padding).\n"
                        + "7. Enter IV For Cipher mode CBC,CTR and GCM Which use for Encryption..\n"
                        + "8. Select Secret Key Size (128->16,192->24,256->32).\n"
                        + "9. Enter Secret Key Which use for Encryption.\n"
                        + "10. Select Output Format (Base64 , Hex).\n"
                        + "11. Click On Decrypt Button File will be Encrypted and Stored.\n\n"

                        + "How to Encrypt Text:\n"
                        + "1. Select Encryption menu.\n"
                        + "2. To Encrypted Text select Encrypt Text Option.\n"
                        + "3. Type the text into the input box.\n"
                        + "4. Select Encryption Cipher mode (ECB,CBC,CTR,GCM).\n"
                        + "5. Select Encryption Padding (PKCS5Padding , No Padding).\n"
                        + "6. Enter IV For Cipher mode CBC,CTR and GCM Or Generate IV.\n"
                        + "7. Select Secret Key Size (128->16,192->24,256->32).\n"
                        + "8. Enter Secret Key Or Generate Secret key.\n"
                        + "9. Select Output Format (Base64 , Hex).\n"
                        + "10. Click On Encrypt Button Text will be Encrypted and Display in Output box.\n"
                        + "11. Save Key details for Decryption.\n\n"

                        + "How to Decrypt Text:\n"
                        + "1. Select Decryption menu.\n"
                        + "2. To Decrypted Text select Decrypt Text Option.\n"
                        + "3. Paste the encrypted text.\n"
                        + "4. Select Decryption Cipher mode (ECB,CBC,CTR,GCM).\n"
                        + "5. Select Decryption Padding (PKCS5Padding , No Padding).\n"
                        + "6. Enter IV For Cipher mode CBC,CTR and GCM Which use for Encryption..\n"
                        + "7. Select Secret Key Size (128->16,192->24,256->32).\n"
                        + "8. Enter Secret Key Which use for Encryption.\n"
                        + "9. Select Output Format (Base64 , Hex).\n"
                        + "10. Click On Decrypt Button File will be Decrypted and Display in Output box.\n\n"

                        + "Encryption Modes:\n"
                        + "ECB - Electronic Codebook: Simple but less secure\n"
                        + "CBC - Cipher Block Chaining: More secure, requires IV\n"
                        + "CTR - Counter: Good for parallelization, requires IV\n"
                        + "GCM - Galois/Counter Mode: Authenticated encryption, requires IV\n\n"

                        + "FAQs:\n"
                        + "Why is my decrypted file unreadable?\n"
                        + "Ensure the encryption key, mode, and padding are correct.\n"
                        + "What if I lose my encryption key?\n"
                        + "You cannot decrypt without the correct key.\n\n"

                        + "Security Best Practices:\n"
                        + "Use strong keys.\n"
                        + "Larger keys provide more security but may be slower.\n"
                        + " -> 128 - Standard AES key size (16 chars)\n"
                        + " -> 192 - Increased security (24 chars)\n"
                        + " -> 256 - Maximum security (32 chars)"
                        + "Never share encryption keys over insecure channels.\n"
                        + "Save your Encryption Configuration details File.\n"
                        + "Backup your encrypted files.\n\n");

        // Add the text area inside a scroll pane
        JScrollPane scrollPane = new JScrollPane(helpText);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        // Add components to the help panel
        helpPanel.add(scrollPane, BorderLayout.CENTER);

        // Set the panel content in the main window
        homeView.setMainPanelContent(helpPanel);
    }

}