package com.tech_titans.model;

public class EncryptionModel {
    private String filePath;
    private String encryptionKey;

    public EncryptionModel(String filePath, String encryptionKey) {
        this.filePath = filePath;
        this.encryptionKey = encryptionKey;
    }

    public String getFilePath() {
        return filePath;
    }

    public String getEncryptionKey() {
        return encryptionKey;
    }
}
