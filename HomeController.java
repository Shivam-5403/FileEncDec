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
            JComboBox<String> paddingComboBox, String ivString, JComboBox<String> keySizeComboBox, String key,
            ButtonGroup formatGroup) {
        byte[] decodedData = Base64.getDecoder().decode(ivString);
        EncryptionModel actualText = new EncryptionModel(inputTextArea.getText(), key,
                cipherModeComboBox.getSelectedItem().toString(), paddingComboBox.getSelectedItem().toString(),decodedData,
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
        JPanel helpPanel = new JPanel();
        helpPanel.add(new JLabel("Help Section - Work in Progress"));
        homeView.setMainPanelContent(helpPanel);
    }
}