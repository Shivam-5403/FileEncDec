package com.tech_titans.model;

import java.util.Arrays;

import javax.crypto.SecretKey;

public class EncryptionModel {
    private String filePath;
    private String encryptionKey;
    private String cipherMode = "CBC"; // ECB, CBC, CTR, GCM
    private String padding; // NoPadding, PKCS5Padding
    private byte[] iv; // Initialization Vector
    private int keySize; // 128, 192, 256
    private String outputFormat; // Base64, Hex
    private String plainText; // For text encryption
    private String encryptedText; // For text decryption
    private String password; // For password-based encryption
    private byte[] salt; // Salt for PBKDF2 key derivation

    // 🔹 Constructor for file encryption
    public EncryptionModel(String filePath, String encryptionKey, String cipherMode, String padding, int keySize, String outputFormat, byte[] iv) {
        this.filePath = filePath;
        this.encryptionKey = encryptionKey;
        this.cipherMode = cipherMode; // Default mode
        this.padding = padding; // Default padding
        this.keySize = keySize; // Default key size
        this.outputFormat = outputFormat; // Default output format
        this.iv = iv;
    }

    // // 🔹 Constructor for file decryption
    // public EncryptionModel(String filePath, String encryptionKey, String cipherMode, 
    //                     String padding, int keySize,String outputFormat, byte[] iv) {
    //     this.filePath = filePath;
    //     this.encryptionKey = encryptionKey;
    //     this.cipherMode = cipherMode; // Default mode
    //     this.padding = padding; // Default padding
    //     this.keySize = keySize; // Default key size
    //     this.outputFormat = outputFormat; // Default output format
    //     this.iv = iv;
    // }

    // 🔹 Constructor for text encryption
    public EncryptionModel(String plainText, String encryptionKey, String cipherMode, 
                        String padding, byte[] iv, int keySize, String outputFormat) {
        this.plainText = plainText;
        this.encryptionKey = encryptionKey;
        this.cipherMode = cipherMode;
        this.padding = padding;
        this.iv = iv;
        this.keySize = keySize;
        this.outputFormat = outputFormat;
    }

    // // 🔹 Constructor for text decryption
    // public EncryptionModel(String encryptedText, String encryptionKey, String cipherMode, 
    //                     String padding, byte[] iv, int keySize, String outputFormat) {
    //     this.encryptedText = encryptedText;
    //     this.encryptionKey = encryptionKey;
    //     this.cipherMode = cipherMode;
    //     this.padding = padding;
    //     this.iv = iv;
    //     this.keySize = keySize;
    //     this.outputFormat = outputFormat;
    // }

    public EncryptionModel(String filePath, String password, byte[] salt, byte[] iv, String cipherMode) {
        this.filePath = filePath;
        this.password = password;
        this.salt = salt;
        this.iv = iv;
        this.cipherMode = cipherMode;
    }

    // 🔹 Getters and Setters
    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getEncryptionKey() {
        return encryptionKey;
    }

    public void setEncryptionKey(String encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public String getCipherMode() {
        return cipherMode;
    }

    public void setCipherMode(String cipherMode) {
        this.cipherMode = cipherMode;
    }

    public String getPadding() {
        return padding;
    }

    public void setPadding(String padding) {
        this.padding = padding;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public String getOutputFormat() {
        return outputFormat;
    }

    public void setOutputFormat(String outputFormat) {
        this.outputFormat = outputFormat;
    }

    public String getPlainText() {
        return plainText;
    }

    public void setPlainText(String plainText) {
        this.plainText = plainText;
    }

    public String getEncryptedText() {
        return encryptedText;
    }

    public void setEncryptedText(String encryptedText) {
        this.encryptedText = encryptedText;
    }

    @Override
    public String toString() {
        return "EncryptionModel{" +
                "filePath='" + filePath + '\'' +
                ", encryptionKey=" + (encryptionKey != null ? "[PROVIDED]" : "NULL") +
                ", password=" + (password != null ? "[PROVIDED]" : "NULL") +
                ", salt=" + Arrays.toString(salt) +
                ", iv=" + Arrays.toString(iv) +
                ", cipherMode='" + cipherMode + '\'' +
                '}';
    }
}
