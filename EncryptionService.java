package com.tech_titans.service;

import com.tech_titans.model.EncryptionModel;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;

public class EncryptionService {
    private static final int GCM_TAG_LENGTH = 128;
    private static final int SALT_LENGTH = 16; // 16-byte salt for PBKDF2
    /**
     * Encrypts a file using AES encryption.
     * @param model The encryption model containing file path, key, and other parameters.
     * @return True if encryption was successful.
     * @throws Exception If encryption fails.
     */
    public static boolean encryptFile(EncryptionModel model) throws Exception {
        File inputFile = new File(model.getFilePath());
    
        // Prefix based on output format
        String prefix = model.getOutputFormat().equalsIgnoreCase("Base64") ? "b64_encrypted_" : "hex_encrypted_";

        // Extract original filename
        String originalName = inputFile.getName();

        File outputFile = new File(inputFile.getParent(), prefix + originalName);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
            FileOutputStream outputStream = new FileOutputStream(outputFile)) {

            ByteArrayOutputStream byteBuffer = new ByteArrayOutputStream();

            if (!model.getCipherMode().equalsIgnoreCase("ECB") && model.getIv() != null) {
                byteBuffer.write(model.getIv()); // IV
            }

            // Compute file integrity hash
            byte[] fileHash = computeFileHash(inputFile);
            // Write file integrity hash before encrypted content
            byteBuffer.write(fileHash);

            // Get cipher instance and initialize
            Cipher cipher = getCipher(model, Cipher.ENCRYPT_MODE);
                
            // Process file content
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    byteBuffer.write(output);
                }
            }

            byte[] finalOutput = cipher.doFinal();
            if (finalOutput != null) {
                byteBuffer.write(finalOutput);
            }

            // Encode to Base64 or Hex
            byte[] encryptedBytes = byteBuffer.toByteArray();
            String formattedOutput = model.getOutputFormat().equalsIgnoreCase("Base64")
                    ? Base64.getEncoder().encodeToString(encryptedBytes)
                    : bytesToHex(encryptedBytes);
            
            outputStream.write(formattedOutput.getBytes(StandardCharsets.UTF_8));

            return true;
        } catch (Exception e) {
            throw new Exception("Encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypts a file using AES decryption.
     * @param model The encryption model containing file path, key, and other parameters.
     * @return True if decryption was successful.
     * @throws Exception If decryption fails.
     */
    public static boolean decryptFile(EncryptionModel model) throws Exception {
        File inputFile = new File(model.getFilePath());

        // Detect format based on prefix
        String fileName = inputFile.getName().toLowerCase();
        boolean isBase64 = fileName.startsWith("b64_");
        boolean isHex = fileName.startsWith("hex_");

        if (!isBase64 && !isHex) {
            throw new Exception("Unknown format: filename must start with 'b64_' or 'hex_'");
        }

         // Remove prefix and add _decrypted before extension
        String baseName = fileName.replaceFirst("^b64_encrypted_|^hex_encrypted_", "");
        String outputName = baseName.replaceAll("(\\.\\w+)$", "_decrypted$1");
        File outputFile = new File(inputFile.getParent(), outputName);

        if (outputFile.exists()) {
            outputFile = new File(inputFile.getParent(), outputName.replace(".", "_copy."));
        }

        try {
        // Read the full content as encoded text
            StringBuilder encodedContent = new StringBuilder();
            try (Scanner scanner = new Scanner(inputFile)) {
                while (scanner.hasNextLine()) {
                    encodedContent.append(scanner.nextLine());
                }
            }

            // Decode to raw bytes
            byte[] allBytes = isBase64
                    ? Base64.getDecoder().decode(encodedContent.toString())
                    : hexToBytes(encodedContent.toString());

            int currentIndex = 0;

            // Extract IV if required
            if (!model.getCipherMode().equalsIgnoreCase("ECB")) {
                byte[] iv = new byte[16];
                System.arraycopy(allBytes, currentIndex, iv, 0, 16);
                model.setIv(iv);
                currentIndex += 16;
            }

            // Extract hash
            byte[] storedFileHash = new byte[32];
            System.arraycopy(allBytes, currentIndex, storedFileHash, 0, 32);
            currentIndex += 32;

            // Prepare cipher
            Cipher cipher = getCipher(model, Cipher.DECRYPT_MODE);

            // Decrypt content
            byte[] decryptedBytes = cipher.doFinal(allBytes, currentIndex, allBytes.length - currentIndex);

            // Write to output
            try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
                outputStream.write(decryptedBytes);
            }

            // Check file integrity
            byte[] newFileHash = computeFileHash(outputFile);
            if (!MessageDigest.isEqual(storedFileHash, newFileHash)) {
                throw new Exception("Integrity check failed: decrypted content doesn't match original.");
            }

            System.out.println("Decrypted file saved: " + outputFile.getAbsolutePath());
            return true;

        } catch (Exception e) {
            throw new Exception("Decryption failed: " + e.getMessage(), e);
        }

    }

    /**
     * Encrypts text using AES encryption.
     * @param model The encryption model containing text, key, and other parameters.
     * @return Encrypted text in Base64 or Hex format.
     * @throws Exception If encryption fails.
     */
    public static String encryptText(EncryptionModel model) throws Exception {
        byte[] input = model.getPlainText().getBytes(StandardCharsets.UTF_8);
        
        // Get cipher instance and initialize
        Cipher cipher = getCipher(model, Cipher.ENCRYPT_MODE);
        
        // Encrypt the text
        byte[] encryptedBytes = cipher.doFinal(input);
        
        // Prepare output
        byte[] outputBytes;
        if (!model.getCipherMode().equals("ECB") && model.getIv() != null) {
            // For modes that use IV, prepend IV to the encrypted bytes
            outputBytes = new byte[model.getIv().length + encryptedBytes.length];
            System.arraycopy(model.getIv(), 0, outputBytes, 0, model.getIv().length);
            System.arraycopy(encryptedBytes, 0, outputBytes, model.getIv().length, encryptedBytes.length);
        } else {
            outputBytes = encryptedBytes;
        }
        
        // Format the output according to preference
        if (model.getOutputFormat().equals("Base64")) {
            return Base64.getEncoder().encodeToString(outputBytes);
        } else { // Hex
            return bytesToHex(outputBytes);
        }
    }
    

    /**
     * Decrypts text using AES decryption.
     * @param model The encryption model containing encrypted text, key, and other parameters.
     * @return Decrypted text as a string.
     * @throws Exception If decryption fails.
     */
    public static String decryptText(EncryptionModel model) throws Exception {
        // Decode the input based on format
        byte[] encryptedData;
        if (model.getOutputFormat().equals("Base64")) {
            encryptedData = Base64.getDecoder().decode(model.getPlainText());
        } else { // Hex
            encryptedData = hexToBytes(model.getPlainText());
        }
        
        // Extract IV if needed
        if (!model.getCipherMode().equals("ECB")) {
            byte[] iv = new byte[16]; // 16 bytes (128 bits) for IV
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);
            model.setIv(iv);
            
            // Skip IV in the encrypted data
            byte[] actualEncryptedData = new byte[encryptedData.length - iv.length];
            System.arraycopy(encryptedData, iv.length, actualEncryptedData, 0, actualEncryptedData.length);
            encryptedData = actualEncryptedData;
        }
        
        // Get cipher instance and initialize
        Cipher cipher = getCipher(model, Cipher.DECRYPT_MODE);
        
        // Decrypt the data
        byte[] decryptedBytes = cipher.doFinal(encryptedData);
        
        // Convert to string
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Generates a random IV (Initialization Vector).
     * @return 16-byte IV.
     */
    public static byte[] generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    

    /**
     * Computes SHA-256 hash of a file.
     * @param file The input file.
     * @return The hash of the file.
     * @throws IOException If reading the file fails.
     * @throws NoSuchAlgorithmException If hashing algorithm is not available.
     */
    private static byte[] computeFileHash(File file) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(file);
            BufferedInputStream bis = new BufferedInputStream(fis)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = bis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }
        return digest.digest();
    }

    /**
     * Derives a secret key from a password using PBKDF2.
     * @param password The user-provided password.
     * @param salt A randomly generated salt.
     * @param iterations The number of iterations (recommended: 65536).
     * @param keySize Key size in bits (128, 192, or 256).
     * @return Derived AES key.
     * @throws NoSuchAlgorithmException If PBKDF2 is not available.
     * @throws InvalidKeySpecException If key generation fails.
     */
    public static SecretKey deriveKeyFromPassword(String password, byte[] salt, int iterations, int keySize)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keySize);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }


    /**
     * Generates a random salt.
     * @return A 16-byte salt.
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return salt;
    }


    /**
     * Generates a random AES key of specified size.
     * @param keySize Key size in bits (128, 192, 256).
     * @return Base64-encoded key.
     * @throws NoSuchAlgorithmException If key generation fails.
     */
    public static String generateKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize);
        SecretKey key = keyGen.generateKey();
        
        // Fix: Use Base64 encoding to ensure correct storage of the key
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Configures and returns a Cipher instance based on model parameters.
     * @param model The encryption model.
     * @param mode Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE.
     * @return Configured Cipher instance.
     * @throws Exception If cipher creation fails.
     */
    private static Cipher getCipher(EncryptionModel model, int mode) throws Exception {
        String cipherMode = model.getCipherMode();

        String padding = model.getPadding();

        String transformation = "AES/" + cipherMode + "/" + padding;

        Cipher cipher = Cipher.getInstance(transformation);

        byte[] keyBytes = Base64.getDecoder().decode(model.getEncryptionKey());

        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        if (cipherMode.equalsIgnoreCase("ECB")) {
            cipher.init(mode, secretKey);
        } else if (cipherMode.equalsIgnoreCase("GCM")) {
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, model.getIv());
            cipher.init(mode, secretKey, spec);
        } else { // CBC, CTR
            IvParameterSpec ivSpec = new IvParameterSpec(model.getIv());

            cipher.init(mode, secretKey, ivSpec);
        }

        return cipher;
    }

    // Helper method to convert bytes to a hex string.
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString().toUpperCase();
    }

    /**
     * Converts a hex string to a byte array.
     */
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
