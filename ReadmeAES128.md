# Readme #
## Сборка ##
См. readme библиотеки libakrypt
## Что сделано ##
Было реализовано встраивание реализации алгоритма блочного шифрования AES-128, регламентированного стандартом FIPS 197 https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

Для встраивания реализции алгоритма шифрования AES-128 в библиотеку были внесены следующие изменения:

* Добавлен файл `source/ak_aes128.c`
* Добавлен файл `examples/test-aes128.c`
* Добавлено описание следующих функций в файл `libakrypt.h`:

        ak_libakrypt_test_aes128( void )            на строке 173
        
        int ak_bckey_create_aes128( ak_bckey )      на строке 684
    
* Добавлены следующие строки в коде файла `CMakeLists.txt`:

        source/ak_aes128.c      на строке 85
        
        aes128                  на строке 196

Файл `ak_aes128.c` содержит реализацию алгоритма блочного шифрования AES-128. В файле определены следующие функции:

Вспомогательные функции:

    static ak_uint8 mul_by_02(ak_uint8 num)
    
    static ak_uint8 mul_by_03(ak_uint8 num)
    
    static ak_uint8 mul_by_09(ak_uint8 num)
    
    static ak_uint8 mul_by_0b(ak_uint8 num)
    
    static ak_uint8 mul_by_0d(ak_uint8 num)
    
    static ak_uint8 mul_by_0e(ak_uint8 num)
    
Основные функции, использующиеся в алгоритме шифрования:

    static void ak_aes128_add_round_key(ak_uint8 * state, ak_uint8 * key_schedule, int round)
    
    static void ak_aes128_sub_bytes(ak_uint8 * state)
    
    static void ak_aes128_inv_sub_bytes(ak_uint8 * state)
    
    static void ak_aes128_shift_rows(ak_uint8 * state)
    
    static void ak_aes128_inv_shift_rows(ak_uint8 * state)
    
    static void ak_aes128_mix_columns(ak_uint8 * state)
    
    static void ak_aes128_inv_mix_columns(ak_uint8 * state)
    
Функции для работы с ключами:

    static int ak_aes128_delete_keys(ak_skey skey)
    
    static int ak_aes128_schedule_keys(ak_skey skey)
    
    static int ak_skey_set_special_aes128_mask(ak_skey skey)
    
    static int ak_skey_set_special_aes128_unmask(ak_skey skey)
    
    int ak_bckey_create_aes128(ak_bckey bkey)
    
Функции зашифрования и расшифрования:

    static void ak_aes128_encrypt(ak_skey skey, ak_pointer in, ak_pointer out)
    
    static void ak_aes128_decrypt(ak_skey skey, ak_pointer in, ak_pointer out)
    
Функция для тестирования работоспособности (параметры взяты из стандарта AES FIPS 197), продублировано в файле `test-aes128.c`:

    bool_t ak_libakrypt_test_aes128(void)
