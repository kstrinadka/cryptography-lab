package com.kstrinadka.hashFunction;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256HashFunction {
    public static String hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(input.getBytes());

            // Преобразуем байты хеша в строку в шестнадцатеричном формате
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String input = "Hello, World!";
        String hashValue = hash(input);
        System.out.println("SHA-256 хеш для строки '" + input + "': " + hashValue);
    }
}