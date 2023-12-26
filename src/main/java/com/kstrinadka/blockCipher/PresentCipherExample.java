package com.kstrinadka.blockCipher;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;

public class PresentCipherExample {

    public static byte[] encrypt(byte[] plaintext, byte[] key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "PRESENT");
        Cipher cipher = Cipher.getInstance("PRESENT");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "PRESENT");
        Cipher cipher = Cipher.getInstance("PRESENT");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(ciphertext);
    }

    public static void main(String[] args) throws Exception {
        byte[] key = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
//        byte[] plaintext = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
        byte[] plaintext = new byte[] { (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF };


        byte[] ciphertext = encrypt(plaintext, key);
        byte[] decryptedText = decrypt(ciphertext, key);

        System.out.println("Plaintext: " + byteArrayToHexString(plaintext));
        System.out.println("Ciphertext: " + byteArrayToHexString(ciphertext));
        System.out.println("Decrypted Text: " + byteArrayToHexString(decryptedText));
    }

    public static String byteArrayToHexString(byte[] array) {
        StringBuilder sb = new StringBuilder();
        for (byte b : array) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}

