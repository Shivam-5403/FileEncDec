package com.tech_titans.view;

import com.tech_titans.controller.HomeController;

import javax.swing.*;
import java.awt.*;

public class HomeView extends JFrame {
    private JButton encryptButton, decryptButton, settingsButton, exitButton;
    private HomeController controller;

    public HomeView() {
        setTitle("File Encryption & Decryption");
        setSize(400, 300);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        controller = new HomeController(this);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new GridLayout(4, 1, 10, 10));

        encryptButton = new JButton("Encrypt File");
        decryptButton = new JButton("Decrypt File");
        settingsButton = new JButton("Settings");
        exitButton = new JButton("Exit");

        mainPanel.add(encryptButton);
        mainPanel.add(decryptButton);
        mainPanel.add(settingsButton);
        mainPanel.add(exitButton);

        add(mainPanel);

        // Attach event listeners to controller
        encryptButton.addActionListener(controller::handleEncrypt);
        decryptButton.addActionListener(controller::handleDecrypt);
        settingsButton.addActionListener(controller::handleSettings);
        exitButton.addActionListener(e -> System.exit(0));
    }

    public void showMessage(String message) {
        JOptionPane.showMessageDialog(this, message);
    }
}
