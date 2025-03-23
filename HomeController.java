package com.tech_titans.controller;

import com.tech_titans.view.HomeView;

import java.awt.event.ActionEvent;

public class HomeController {
    private HomeView view;

    public HomeController(HomeView view) {
        this.view = view;
    }

    public void handleEncrypt(ActionEvent e) {
        view.showMessage("Encryption Module Coming Soon!");
    }

    public void handleDecrypt(ActionEvent e) {
        view.showMessage("Decryption Module Coming Soon!");
    }

    public void handleSettings(ActionEvent e) {
        view.showMessage("Settings Module Coming Soon!");
    }
}
