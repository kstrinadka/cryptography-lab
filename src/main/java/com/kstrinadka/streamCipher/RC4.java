package com.kstrinadka.streamCipher;

public class RC4 {

    // Перестановка, содержащая все возможные байты от 0x00 до 0xFF (массив S).
    int[] S = new int[256];

    // Переменные-счетчики.
    int x = 0;
    int y = 0;

    public RC4(byte[] key) {
        init(key);
    }

    /**
     * Для каждого байта массива/потока входных незашифрованных данных запрашиваем байт ключа и
     * объединяем их при помощи xor (^).
     *
     * @param dataB -- массив байтов, который представляет собой исходные данные, которые необходимо зашифровать.
     * @param size -- количество байтов, которое нужно взять из dataB для шифрования.
     * @return -- зашифрованные данные.
     */
    public byte[] encode(byte[] dataB, int size) {
        byte[] data = new byte[size];
        System.arraycopy(dataB, 0, data, 0, size);

        byte[] cipher = new byte[data.length];

        for (int m = 0; m < data.length; m++) {
            cipher[m] = (byte) (data[m] ^ this.keyItem());
        }

        return cipher;
    }

    public byte[] decode(byte[] dataB, int size)
    {
        return encode(dataB, size);
    }

    /**
     * Алгоритм ключевого расписания (Key-Scheduling Algorithm).
     *
     * @param key -- начальный секретный ключ
     */
    private void init(byte[] key) {
        int keyLength = key.length;

        for (int i = 0; i < 256; i++) {
            S[i] = i;
        }

        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (((j + S[i] + key[i % keyLength]) % 256) + 256) % 256;
            swap(S, i, j);
        }
    }


    /**
     * Генератор псевдослучайной последовательности (Pseudo-Random Generation Algorithm).
     *
     * @return -- последующий байт ключевого потока, который будем объединять xor'ом c байтом исходных данных.
     */
    private int keyItem() {
        x = (x + 1) % 256;
        y = (y + S[x]) % 256;

        swap(S, x, y);

        return S[(S[x] + S[y]) % 256];
    }

    private static void swap(int[] a, int i, int j) {
        int t = a[i];
        a[i] = a[j];
        a[j] = t;
    }
}
