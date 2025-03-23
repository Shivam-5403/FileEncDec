package com.tech_titans.controller;

import com.tech_titans.view.HomeView;

import java.awt.event.ActionEvent;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

public class HomeController {
    private HomeView homeView;

    public HomeController(HomeView homeView) {
        this.homeView = homeView;
    }

    public void handleEncrypt(ActionEvent e) {
        homeView.updateStatus("Encrypting File...");
        JPanel encryptPanel = new JPanel();
        encryptPanel.add(new JLabel("Encryption Panel - Work in Progress"));
        homeView.setMainPanelContent(encryptPanel);    }

    public void handleDecrypt(ActionEvent e) {
        homeView.updateStatus("Decrypting File...");
        JPanel decryptPanel = new JPanel();
        decryptPanel.add(new JLabel("Decryption Panel - Work in Progress"));
        homeView.setMainPanelContent(decryptPanel);
    }

    public void handleSettings(ActionEvent e) {
        homeView.updateStatus("Opening Settings...");
        JPanel settingsPanel = new JPanel();
        settingsPanel.add(new JLabel("Settings Panel - Work in Progress"));
        homeView.setMainPanelContent(settingsPanel);
    }

    public void handleOpenFile(ActionEvent e) {
        homeView.updateStatus("Opening File...");
        JOptionPane.showMessageDialog(null, "File Open Dialog Placeholder");
    }

    public void handleHelp(ActionEvent e) {
        homeView.updateStatus("Opening Help...");
        JPanel helpPanel = new JPanel();
        helpPanel.add(new JLabel("Help Section - Work in Progress"));
        homeView.setMainPanelContent(helpPanel);
    }
}
