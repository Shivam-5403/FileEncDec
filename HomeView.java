package com.tech_titans.view;

import com.tech_titans.controller.HomeController;
import javax.swing.*;
import java.awt.*;

public class HomeView extends JFrame {
    private JPanel mainPanel; // Panel to load different content dynamically
    private JProgressBar progressBar;
    private HomeController controller;

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
        JMenuItem decryptOption = new JMenuItem("Decrypt File");
        JMenuItem settingsOption = new JMenuItem("Preferences");
        JMenuItem aboutOption = new JMenuItem("About");

        // Add items to their respective menus
        fileMenu.add(openFileItem);
        fileMenu.add(exitItem);
        encryptMenu.add(encryptOption);
        decryptMenu.add(decryptOption);
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
        encryptOption.addActionListener(controller::handleEncrypt);
        decryptOption.addActionListener(controller::handleDecrypt);
        settingsOption.addActionListener(controller::handleSettings);
        aboutOption.addActionListener(controller::handleHelp);

        setVisible(true);
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
}
