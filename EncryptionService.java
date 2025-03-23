package com.tech_titans.service;

import com.tech_titans.model.EncryptionModel;

public class EncryptionService {
    public static boolean encryptFile(EncryptionModel model) {
        System.out.println("Encrypting: " + model.getFilePath());
        return true;
    }

    public static boolean decryptFile(EncryptionModel model) {
        System.out.println("Decrypting: " + model.getFilePath());
        return true;
    }
}
