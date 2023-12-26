package com.kstrinadka.blockCipher;

public class PresentCipherImpl {


    // Константы для алгоритма
    private static final int BLOCK_SIZE = 64; // Размер блока в битах
    private static final int KEY_SIZE = 80; // Размер ключа в битах
    private static final int ROUNDS = 31; // Количество раундов шифрования
    private static final int[] SBOX = {0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2}; // S-блок для нелинейного преобразования
    private static final long[] RC = { // Константы раундов для генерации подключей
            0x0000000000000000L,
            0x0000000000000080L,
            0x00000000000000C0L,
            0x00000000000002C0L,
            0x00000000000003C0L,
            0x0000000000000BC0L,
            0x0000000000000FC0L,
            0x0000000000002FC0L,
            0x0000000000003FC0L,
            0x000000000000BFC0L,
            0x000000000000FFC0L,
            0x000000000002FFC0L,
            0x000000000003FFC0L,
            0x00000000000BFFC0L,
            0x00000000000FFFC0L,
            0x00000000002FFFC0L,
            0x800100002FFFFC00L,
            0xC0018002FFFFC080L,
            0xC001C002FFFFC080L,
            0xC001E002FFFFC280L,
            0xC001F002FFFFC380L,
            0xC001F802FFFFCB80L,
            0xC001FC02FFFFCF80L,
            0xC001FE02FFFFEFC8L,
            0xC001FF02FFFFEFC8L,
            0xC001FF82FFFFEFCCL,
            0xC001FFC2FFFFEFCEL,
            1 << (BLOCK_SIZE - ROUNDS),
    };

    // Метод для шифрования блока данных
    public byte[] encrypt(byte[] data, byte[] key) {
        // Проверка входных данных
        if (data == null || data.length != BLOCK_SIZE / Byte.SIZE) {
            throw new IllegalArgumentException("Invalid data size");
        }
        if (key == null || key.length != KEY_SIZE / Byte.SIZE) {
            throw new IllegalArgumentException("Invalid key size");
        }

        // Преобразование байтовых массивов в числа
        long state = bytesToLong(data); // Состояние блока данных
        long k = bytesToLong(key); // Ключ

        // Цикл шифрования
        for (int i = 1; i <= ROUNDS; i++) {
            // Добавление подключа к состоянию
            state ^= k;

            // Нелинейное преобразование с помощью S-блока
            state = sBoxLayer(state);

            // Линейное преобразование с помощью P-блока
            state = pLayer(state);

            // Генерация подключа для следующего раунда
            k = updateKey(k, i);
        }

        // Добавление последнего подключа к состоянию
        state ^= k;

        // Преобразование числа в байтовый массив и возвращение результата
        return longToBytes(state);
    }

    // Метод для расшифровки блока данных
    public byte[] decrypt(byte[] data, byte[] key) {
        // Проверка входных данных
        if (data == null || data.length != BLOCK_SIZE / Byte.SIZE) {
            throw new IllegalArgumentException("Invalid data size");
        }
        if (key == null || key.length != KEY_SIZE / Byte.SIZE) {
            throw new IllegalArgumentException("Invalid key size");
        }

        // Преобразование байтовых массивов в числа
        long state = bytesToLong(data); // Состояние блока данных
        long k = bytesToLong(key); // Ключ

        // Цикл расшифровки
        for (int i = ROUNDS; i >= 1; i--) {
            // Добавление подключа к состоянию
            state ^= k;

            // Обратное линейное преобразование с помощью P-блока
            state = inversePLayer(state);

            // Обратное нелинейное преобразование с помощью S-блока
            state = inverseSBoxLayer(state);

            // Генерация подключа для предыдущего раунда
            k = updateKey(k, i);
        }

        // Добавление последнего подключа к состоянию
        state ^= k;

        // Преобразование числа в байтовый массив и возвращение результата
        return longToBytes(state);
    }

    // Метод для применения S-блока к состоянию
    private long sBoxLayer(long state) {
        long result = 0; // Результат преобразования
        for (int i = 0; i < BLOCK_SIZE; i += 4) { // Цикл по четырем битам состояния
            int nibble = (int) ((state >>> i) & 0xF); // Извлечение четырех битов состояния
            nibble = SBOX[nibble]; // Применение S-блока к четырем битам
            result |= ((long) nibble) << i; // Добавление четырех битов к результату
        }
        return result;
    }

    // Метод для применения обратного S-блока к состоянию
    private long inverseSBoxLayer(long state) {
        long result = 0; // Результат преобразования
        for (int i = 0; i < BLOCK_SIZE; i += 4) { // Цикл по четырем битам состояния
            int nibble = (int) ((state >>> i) & 0xF); // Извлечение четырех битов состояния
            nibble = inverseSBox(nibble); // Применение обратного S-блока к четырем битам
            result |= ((long) nibble) << i; // Добавление четырех битов к результату
        }
        return result;
    }

    // Метод для нахождения обратного значения S-блока для данного значения
    private int inverseSBox(int value) {
        for (int i = 0; i < SBOX.length; i++) { // Цикл по всем значениям S-блока
            if (SBOX[i] == value) { // Если значение найдено в S-блоке, то вернуть его индекс
                return i;
            }
        }
        return -1; // Если значение не найдено в S-блоке, то вернуть -1
    }

    // Метод для применения P-блока к состоянию
    private long pLayer(long state) {
        long result = 0; // Результат преобразования
        for (int i = 0; i < BLOCK_SIZE; i++) { // Цикл по всем битам состояния
            int bit = (int) ((state >>> i) & 1); // Извлечение одного бита состояния
            int position = (i * 16) % 63; // Вычисление новой позиции бита с помощью P-блока
            if (i == 63) { // Особый случай для последнего бита, который не меняется местами
                position = 63;
            }
            result |= (long) bit << position; // Добавление одного бита к результату
        }
        return result;
    }

    // Метод для применения обратного P-блока к состоянию
    private long inversePLayer(long state) {
        long result = 0; // Результат преобразования
        for (int i = 0; i < BLOCK_SIZE; i++) { // Цикл по всем битам состояния
            int bit = (int) ((state >>> i) & 1); // Извлечение одного бита состояния
            int position = (i * 16) % 63; // Вычисление старой позиции бита с помощью P-блока
            if (position == 63) { // Особый случай для последнего бита, который не меняется местами
                position = 63;
            }
            result |= ((long) bit) << position; // Добавление одного бита к результату
        }
        return result;
    }

    // Метод для генерации подключа для заданного раунда
    private long updateKey(long key, int round) {
        long result = key; // Результат преобразования

        // Циклический сдвиг ключа на 61 позицию влево
        result = (result << 61) | (result >>> (KEY_SIZE - 61));

        // Нелинейное преобразование четырех старших битов ключа с помощью S-блока
        int nibble = (int) ((result >>> (KEY_SIZE - 4)) & 0xF); // Извлечение четырех старших битов ключа
        nibble = SBOX[nibble]; // Применение S-блока к четырем битам
        result &= ~(0xFL << (KEY_SIZE - 4)); // Обнуление четырех старших битов ключа
        result |= ((long) nibble) << (KEY_SIZE - 4); // Добавление четырех битов к ключу

        // Исключающее или младших пяти битов ключа с константой раунда
        result ^= RC[round];

        return result;
    }

    // Метод для преобразования байтового массива в число типа long
    private long bytesToLong(byte[] bytes) {
        long result = 0; // Результат преобразования
        for (int i = 0; i < bytes.length; i++) { // Цикл по всем байтам массива
            result <<= Byte.SIZE; // Сдвиг результата на размер одного байта влево
            result |= (bytes[i] & 0xFF); // Добавление одного байта к результату с учетом знака
        }
        return result;
    }

    // Метод для преобразования числа типа long в байтовый массив
    private byte[] longToBytes(long value) {
        byte[] result = new byte[Long.SIZE / Byte.SIZE]; // Результат преобразования
        for (int i = result.length - 1; i >= 0; i--) { // Цикл по всем байтам массива в обратном порядке
            result[i] = (byte) (value & 0xFF); // Извлечение младшего байта числа и добавление его к массиву
            value >>>= Byte.SIZE; // Сдвиг числа на размер одного байта вправо без учета знака
        }
        return result;
    }

}
