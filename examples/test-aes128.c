/* ----------------------------------------------------------------------------------------------- */
/*                 Тестирование алгоритма блочного шифрования AES-128 (FIPS 197).                  */
/* ----------------------------------------------------------------------------------------------- */

#include <stdio.h>
#include <libakrypt.h>

int main()
{
    ak_uint8 for_enc[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    ak_uint8 key_enc[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    ak_uint8 out_enc[16];

    struct bckey key;
    if (ak_bckey_create_aes128(&key) != ak_error_ok)
    {
        printf("Ошибка ak_bckey_create_aes128\n");
        return -1;
    }

    if (ak_bckey_set_key(&key, key_enc, 16) != ak_error_ok)
    {
        printf("Ошибка ak_bckey_set_key\n");
        return -1;
    }

    if (ak_bckey_encrypt_ecb(&key, for_enc, out_enc, 16) != ak_error_ok)
    {
        printf("Ошибка ak_bckey_encrypt_ecb\n");
        return -1;
    }

    printf("Зашифрование: \n");
    printf("Ключ: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%X ", key_enc[i]);
    }

    printf("\nВходные данные: ");
    for (int i = 0; i < 16; i++)
    {
       printf("%X ", for_enc[i]);
    }

    printf("\nРезультат: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%X ", out_enc[i]);
    }


    ak_uint8 for_dec[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    ak_uint8 key_dec[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    ak_uint8 out_dec[16];

    if (ak_bckey_set_key(&key, key_dec, 16) != ak_error_ok)
    {
        printf("Ошибка ak_bckey_set_key\n");
        return -1;
    }
    if (ak_bckey_decrypt_ecb(&key, for_dec, out_dec, 16 ) != ak_error_ok)
    {
        printf("Ошибка ak_bckey_decrypt_ecb\n");
        return -1;
    }

    printf("\n\nРасшифрование: \n");
    printf("Ключ: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%X ", key_dec[i]);
    }

    printf("\nВходное сообщение: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%X ", for_dec[i]);
    }

    printf("\nРезультат: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%X ", out_dec[i]);
    }
    printf("\n");

    return 0;
}
