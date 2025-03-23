package com.tech_titans.controller;

import com.tech_titans.view.HomeView;

import java.awt.event.ActionEvent;
import java.io.File;

import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

public class HomeController {
    private HomeView homeView;
    private File selectedFile;

    public HomeController(HomeView homeView) {
        this.homeView = homeView;
    }

    public void handleEncrypt(ActionEvent e) {
        // homeView.updateStatus("Encrypting File...");
        // JPanel encryptPanel = new JPanel();
        // encryptPanel.add(new JLabel("Encryption Panel - Work in Progress"));
        // homeView.setMainPanelContent(encryptPanel);
        if (selectedFile == null) {
            homeView.showMessage("Please select a file first!");
            return;
        }
        homeView.updateStatus("Encrypting: " + selectedFile.getName());   
    }

    public void handleDecrypt(ActionEvent e) {
        // homeView.updateStatus("Decrypting File...");
        // JPanel decryptPanel = new JPanel();
        // decryptPanel.add(new JLabel("Decryption Panel - Work in Progress"));
        // homeView.setMainPanelContent(decryptPanel);
        if (selectedFile == null) {
            homeView.showMessage("Please select a file first!");
            return;
        }
        homeView.updateStatus("Decrypting: " + selectedFile.getName());
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
