package com.kstrinadka.streamCipher;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class RC4Example {
    public static void main(String[] args) throws Exception {
        myRC4Encode();
        System.out.println();

        // для сравнения с уже реализованным стандартным алгоритмом
        standartRC4Encode();
    }

    public static void myRC4Encode() throws Exception {
        // Ключ для шифрования/дешифрования
        String key = "keyforencode";

        // Исходный текст для шифрования
        String testString = "Plaintext";

        // Преобразование ключа и исходного текста в массивы байт
        byte[] keyBytes = key.getBytes(StandardCharsets.US_ASCII);
        byte[] testBytes = testString.getBytes(StandardCharsets.US_ASCII);

        // Шифрование
        byte[] encryptedBytes = myRC4Encrypt(keyBytes, testBytes);

        // Дешифрование
        byte[] decryptedBytes = myRC4Encrypt(keyBytes, encryptedBytes);

        // Преобразование байтов в строки
        String decryptedString = new String(decryptedBytes, StandardCharsets.US_ASCII);

        // Вывод результатов
        System.out.println("Зашифровано: " + bytesToHexString(encryptedBytes));
        System.out.println("Дешифровано: " + decryptedString);

    }

    public static byte[] myRC4Encrypt(byte[] key, byte[] data) throws Exception {
        RC4 encoder = new RC4(key);
        byte[] result = encoder.encode(data, data.length);
        return result;
    }

    public static void standartRC4Encode() throws Exception {
        // Ключ для шифрования/дешифрования
        String key = "keyforencode";

        // Исходный текст для шифрования
        String testString = "Plaintext";

        // Преобразование ключа и исходного текста в массивы байт
        byte[] keyBytes = key.getBytes(StandardCharsets.US_ASCII);
        byte[] testBytes = testString.getBytes(StandardCharsets.US_ASCII);

        // Шифрование
        byte[] encryptedBytes = rc4Encrypt(keyBytes, testBytes);

        // Дешифрование
        byte[] decryptedBytes = rc4Encrypt(keyBytes, encryptedBytes);

        // Преобразование байтов в строки
        String decryptedString = new String(decryptedBytes, StandardCharsets.US_ASCII);

        // Вывод результатов
        System.out.println("Зашифровано: " + bytesToHexString(encryptedBytes));
        System.out.println("Дешифровано: " + decryptedString);
    }

    public static byte[] rc4Encrypt(byte[] key, byte[] data) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "RC4");
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    public static String bytesToHexString(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
}

