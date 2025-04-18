package com.tech_titans.service;

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class FileTransferService {
    private static final int DEFAULT_PORT = 9999;
    private ExecutorService executorService = Executors.newFixedThreadPool(5);
    private boolean serverRunning = false;
    private ServerSocket serverSocket;

    // Send a file to a specified IP address
    public void sendFile(File file, String ipAddress, int port, ProgressCallback callback) throws IOException {
        executorService.submit(() -> {
            try (Socket socket = new Socket(ipAddress, port);
                    FileInputStream fileInputStream = new FileInputStream(file);
                    BufferedOutputStream outputStream = new BufferedOutputStream(socket.getOutputStream())) {

                // Send file name first
                DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
                dataOutputStream.writeUTF(file.getName());

                // Send file size
                long fileSize = file.length();
                dataOutputStream.writeLong(fileSize);

                // Send file content
                byte[] buffer = new byte[4096];
                int bytesRead;
                long totalBytesSent = 0;

                while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                    totalBytesSent += bytesRead;
                    if (callback != null) {
                        int progress = (int) ((totalBytesSent * 100) / fileSize);
                        callback.onProgressUpdate(progress);
                    }
                }
                outputStream.flush();

                if (callback != null) {
                    callback.onTransferComplete(file.getName());
                }
            } catch (IOException e) {
                if (callback != null) {
                    callback.onTransferError(e.getMessage());
                }
            }
        });
    }

    // Start a server to receive files
    public void startReceiveServer(String saveDirectory, ProgressCallback callback) throws IOException {
        if (serverRunning) {
            return;
        }

        serverSocket = new ServerSocket(DEFAULT_PORT);
        serverRunning = true;

        executorService.submit(() -> {
            try {
                while (serverRunning) {
                    Socket clientSocket = serverSocket.accept();
                    handleIncomingFile(clientSocket, saveDirectory, callback);
                }
            } catch (IOException e) {
                if (!serverSocket.isClosed() && callback != null) {
                    callback.onTransferError("Server error: " + e.getMessage());
                }
            }
        });

        if (callback != null) {
            callback.onServerStarted(serverSocket.getLocalPort());
        }
    }

    // Stop the receiving server
    public void stopReceiveServer() {
        serverRunning = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Handle an incoming file connection
    private void handleIncomingFile(Socket socket, String saveDirectory, ProgressCallback callback) {
        executorService.submit(() -> {
            try (DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                    BufferedInputStream inputStream = new BufferedInputStream(socket.getInputStream())) {

                // Read file name
                String fileName = dataInputStream.readUTF();

                // Read file size
                long fileSize = dataInputStream.readLong();

                // Create the output file
                File outputFile = new File(saveDirectory, fileName);
                try (FileOutputStream fileOutputStream = new FileOutputStream(outputFile)) {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    long totalBytesRead = 0;

                    while (totalBytesRead < fileSize &&
                            (bytesRead = inputStream.read(buffer, 0,
                                    (int) Math.min(buffer.length, fileSize - totalBytesRead))) != -1) {
                        fileOutputStream.write(buffer, 0, bytesRead);
                        totalBytesRead += bytesRead;

                        if (callback != null) {
                            int progress = (int) ((totalBytesRead * 100) / fileSize);
                            callback.onProgressUpdate(progress);
                        }
                    }

                    if (callback != null) {
                        callback.onFileReceived(outputFile.getAbsolutePath());
                    }
                }
            } catch (IOException e) {
                if (callback != null) {
                    callback.onTransferError("Error receiving file: " + e.getMessage());
                }
            }
        });
    }

    // Callback interface for progress updates
    public interface ProgressCallback {
        void onProgressUpdate(int progressPercentage);

        void onTransferComplete(String fileName);

        void onFileReceived(String filePath);

        void onServerStarted(int port);

        void onTransferError(String errorMessage);
    }

    // Get local IP address (useful for displaying to user)
    public String getLocalIPAddress() {
        try {
            return InetAddress.getLocalHost().getHostAddress();
        } catch (UnknownHostException e) {
            return "127.0.0.1";
        }
    }
}