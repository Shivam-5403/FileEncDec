package com.tech_titans.main;

import com.tech_titans.view.HomeView;

import javax.swing.*;

public class MainApp {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new HomeView().setVisible(true));
    }
}