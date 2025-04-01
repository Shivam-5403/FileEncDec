package com.tech_titans.controller;

import com.tech_titans.service.EncryptionService;
import com.tech_titans.view.HomeView;
import com.tech_titans.model.EncryptionModel;

import java.awt.event.ActionEvent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;

public class HomeController {
    private HomeView homeView;
    private File selectedFile;

    // private JRadioButton fileRadioButton;
    // private JRadioButton textRadioButton;
    // private JTextArea inputTextArea;
    // private JTextArea outputTextArea;
    // private JComboBox<String> cipherModeComboBox;
    // private JComboBox<String> paddingComboBox;
    // private JTextField ivTextField;
    // private JComboBox<String> keySizeComboBox;
    // private JPasswordField secretKeyField;
    // private JRadioButton base64RadioButton;
    // private JRadioButton hexRadioButton;
    // private JButton generateIvButton;
    // private JButton generateKeyButton;
    // private JProgressBar operationProgressBar;

    public HomeController(HomeView homeView) {
        this.homeView = homeView;
    }

    public void handleFileEncrypt(ActionEvent e) {
        // homeView.updateStatus("Encrypting File...");
        // JPanel encryptPanel = new JPanel();
        // encryptPanel.add(new JLabel("Encryption Panel - Work in Progress"));
        // homeView.setMainPanelContent(encryptPanel);
        if (selectedFile == null) {
            homeView.showMessage("Please select a file first!");
            return;
        } else {
            JPanel EncPanel = homeView.EncryptionView(selectedFile);

            homeView.setMainPanelContent(EncPanel);
        }
        homeView.updateStatus("Encrypting: " + selectedFile.getName());
    }

    public void handleFileDecrypt(ActionEvent e) {
        // homeView.updateStatus("Decrypting File...");
        // JPanel decryptPanel = new JPanel();
        // decryptPanel.add(new JLabel("Decryption Panel - Work in Progress"));
        // homeView.setMainPanelContent(decryptPanel);
        if (selectedFile == null) {
            homeView.showMessage("Please select a file first!");
            return;
        } else if (!selectedFile.getName().endsWith(".encrypted")) {
            homeView.showMessage("Selected file is not an encrypted file (.encrypted)!");
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
        EncryptionModel actualFile = new EncryptionModel(selectedFile.getPath(), key,
                cipherModeComboBox.getSelectedItem().toString(), paddingComboBox.getSelectedItem().toString(),
                Integer.parseInt(keySizeComboBox.getSelectedItem().toString()), formatGroup.getSelection().toString(),
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
        byte[] decodedData = Base64.getDecoder().decode(ivString);
        EncryptionModel actualFile = new EncryptionModel(selectedFile.getPath(), key,
                cipherModeComboBox.getSelectedItem().toString(), paddingComboBox.getSelectedItem().toString(),
                Integer.parseInt(keySizeComboBox.getSelectedItem().toString()), formatGroup.getSelection().toString(),
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
            homeView.updateStatus("Your File has been Decrypted.");
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
        EncryptionModel actualText = new EncryptionModel(inputTextArea.getText(), key,
                cipherModeComboBox.getSelectedItem().toString(), paddingComboBox.getSelectedItem().toString(),
                decodedData, Integer.parseInt(keySizeComboBox.getSelectedItem().toString()),
                formatGroup.getSelection().toString());
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
        EncryptionModel actualText = new EncryptionModel(inputTextArea.getText(), key,
                cipherModeComboBox.getSelectedItem().toString(), paddingComboBox.getSelectedItem().toString(),
                decodedData,
                Integer.parseInt(keySizeComboBox.getSelectedItem().toString()), formatGroup.getSelection().toString());
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

    private void showFileSelectionPanel() {
        JPanel panel = new JPanel();
        panel.add(new JLabel("Selected File: " + selectedFile.getAbsolutePath()));
        homeView.setMainPanelContent(panel);
    }

    public void handleHelp(ActionEvent e) {
        homeView.updateStatus("Opening Help...");

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