/* ----------------------------------------------------------------------------------------------- */
/*  Реализация блочного алгоритма шифрования AES-128, регламентированного стандартом FIPS 197.     */
/* ----------------------------------------------------------------------------------------------- */


#include <libakrypt-internal.h>
#include <libakrypt.h>


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Таблица нелинейной замены, использующейся для зашифрования и алгоритма развертки ключа
    (KeyExpansion) в алгоритме AES-128 (FIPS 197). */
/* ---------------------------------------------------------------------------------------------- */
static const sbox SBOX = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                          0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                          0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                          0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                          0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                          0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                          0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                          0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                          0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                          0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                          0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                          0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                          0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                          0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                          0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                          0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};


/* ---------------------------------------------------------------------------------------------- */
/*! \brief Таблица нелинейной замены, использующейся для расшифрования
    в алгоритме AES-128 (FIPS 197).                                                               */
/* ---------------------------------------------------------------------------------------------- */
static const sbox INV_SBOX = {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
                              0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
                              0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
                              0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
                              0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
                              0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
                              0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
                              0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
                              0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
                              0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
                              0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                              0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
                              0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
                              0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
                              0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
                              0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};


/* ---------------------------------------------------------------------------------------------- */
/*! \brief Константная таблица слов, испольщующаяся для развертки ключей (KeyExpansion)
     в алгоритме AES-128 (FIPS 197).                                                              */
/* ---------------------------------------------------------------------------------------------- */
static const ak_uint8 RCON[4][10] = {{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36},
                                     {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                                     {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                                     {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};


/* ---------------------------------------------------------------------------------------------- */
/*! \brief Развернутые раундовые ключи алгоритма AES-128
    \details Массив содержит записанные последовательно ключи - входной ключ и 10 раундовых ключей.
    Каждый ключ содержит 16 слов (распроложенные последовательно элементы матрицы 4х4). */
/* ---------------------------------------------------------------------------------------------- */
typedef ak_uint8 ak_aes128_expanded_keys[176];


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вспомогательная функция для умножения на {02} в поле. Требуется для операции
    "смешивания" столбцов матрицы сообщения (MixColumns) при зашифровании.                         */
/* ----------------------------------------------------------------------------------------------- */
static ak_uint8 mul_by_02(ak_uint8 num)
{
    ak_uint8 res;
    if (num < 0x80)
    {
        res = num << 1;
    }
    else
    {
         res = (num << 1) ^ 0x1b;
    }

    return res % 0x100;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вспомогательная функция для умножения на {02} в поле. Требуется для операции
    "смешивания" столбцов матрицы сообщения (MixColumns) при зашифровании.                         */
/* ----------------------------------------------------------------------------------------------- */
static ak_uint8 mul_by_03(ak_uint8 num)
{
    return mul_by_02(num) ^ num;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вспомогательная функция для умножения на {09} в поле. Требуется для операции
    "смешивания" столбцов матрицы сообщения (InvMixColumns) при расшифровании.                     */
/* ----------------------------------------------------------------------------------------------- */
static ak_uint8 mul_by_09(ak_uint8 num)
{
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ num;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вспомогательная функция для умножения на {0b} в поле. Требуется для операции
    "смешивания" столбцов матрицы сообщения (InvMixColumns) при расшифровании.                     */
/* ----------------------------------------------------------------------------------------------- */
static ak_uint8 mul_by_0b(ak_uint8 num)
{
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(num) ^ num;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вспомогательная функция для умножения на {0d} в поле. Требуется для операции
    "смешивания" столбцов матрицы сообщения (InvMixColumns) при расшифровании.                     */
/* ----------------------------------------------------------------------------------------------- */
static ak_uint8 mul_by_0d(ak_uint8 num)
{
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ num;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вспомогательная функция для умножения на {0e} в поле. Требуется для операции
    "смешивания" столбцов матрицы сообщения (InvMixColumns) при расшифровании.                     */
/* ----------------------------------------------------------------------------------------------- */
static ak_uint8 mul_by_0e(ak_uint8 num)
{
     return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ mul_by_02(num);
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция, осуществляющая операцию наложения раундового ключа
    по модулю два (AddRoundKey) алгоритма AES-128.                                                 */
/* ----------------------------------------------------------------------------------------------- */
static void ak_aes128_add_round_key(ak_uint8 * state, ak_uint8 * key_schedule, int round)
{
    int col;
    for (col = 0; col < 4; col++)
    {
        state[0 + col * 4] = state[0 + col * 4] ^ key_schedule[0 + (4 * round + col) * 4];
        state[1 + col * 4] = state[1 + col * 4] ^ key_schedule[1 + (4 * round + col) * 4];
        state[2 + col * 4] = state[2 + col * 4] ^ key_schedule[2 + (4 * round + col) * 4];
        state[3 + col * 4] = state[3 + col * 4] ^ key_schedule[3 + (4 * round + col) * 4];
    }
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция, осуществляющая параллельное применение нелинейной перестановки
    для алгоритма зашифрования (SubBytes) AES-128.                                                 */
/* ----------------------------------------------------------------------------------------------- */
static void ak_aes128_sub_bytes(ak_uint8 * state)
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j ++)
        {
            state[i * 4 + j] = SBOX[16 * (state[i * 4 + j] / 0x10) + state[i * 4 + j] % 0x10];
        }
    }
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция, осуществляющая параллельное применение нелинейной перестановки
    для алгоритма расшифрования (InvSubBytes) AES-128.                                             */
/* ----------------------------------------------------------------------------------------------- */
static void ak_aes128_inv_sub_bytes(ak_uint8 * state)
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j ++)
        {
            state[i * 4 + j] = INV_SBOX[16 * (state[i * 4 + j] / 0x10) + state[i * 4 + j] % 0x10];
        }
    }
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция, осуществляющая перестановку байт сообщения (ShiftRows)
    для алгоритма зашифрования AES-128.                                                            */
/* ----------------------------------------------------------------------------------------------- */
static void ak_aes128_shift_rows(ak_uint8 * state)
{
    ak_uint8 tmp_arr[4];
    int i, c, count;

    for (count = 1; count < 4; count++)
    {
        for (c = 1; c <= count; c++)
        {
            for (i = 0; i < 4; i++)
            {
                if (i - 1 >= 0)
                {
                    tmp_arr[i - 1] = state[i * 4 + count];
                }
                else
                {
                    tmp_arr[3] = state[i * 4 + count];
                }
            }

            for (i = 0; i < 4; i++)
            {
                 state[i * 4 + count] = tmp_arr[i];
            }
        }
    }
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция, осуществляющая перестановку байт сообщения (InvShiftRows)
    для алгоритма расшифрования AES-128.                                                           */
/* ----------------------------------------------------------------------------------------------- */
static void ak_aes128_inv_shift_rows(ak_uint8 * state)
{
    ak_uint8 tmp_arr[4];
    int i, c, count;

    for (count = 1; count < 4; count++)
    {
        for (c = 1; c <= count; c++)
        {
            for (i = 0; i < 4; i++)
            {
                if (i + 1 < 4)
                {
                    tmp_arr[i + 1] = state[i * 4 + count];
                }
                else
                {
                    tmp_arr[0] = state[i * 4 + count];
                }
            }

            for (i = 0; i < 4; i++)
            {
                state[i * 4 + count] = tmp_arr[i];
            }
        }
    }
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция, осуществляющая операцию "смешивания" столбцов матрицы сообщения (MixColumns)
    (путем домножения на фиксированный многочлен) для алгоритма зашифрования AES-128.
    Для преобразований используются вспомогательные функции, упрощающие умножение в конечном поле. */
/* ----------------------------------------------------------------------------------------------- */
static void ak_aes128_mix_columns(ak_uint8 * state)
{
    int i;
    ak_uint8 s0, s1, s2, s3;
    for (i = 0; i < 4; i++)
    {
        s0 = mul_by_02(state[0 + i * 4]) ^ mul_by_03(state[1 + i * 4]) ^ state[2 + i * 4] ^ state[3 + i * 4];
        s1 = state[0 + i * 4] ^ mul_by_02(state[1 + i * 4]) ^ mul_by_03(state[2 + i * 4]) ^ state[3 + i * 4];
        s2 = state[0 + i * 4] ^ state[1 + i * 4] ^ mul_by_02(state[2 + i * 4]) ^ mul_by_03(state[3 + i * 4]);
        s3 = mul_by_03(state[0 + i * 4]) ^ state[1 + i * 4] ^ state[2 + i * 4] ^ mul_by_02(state[3 + i * 4]);

        state[0 + i * 4] = s0;
        state[1 + i * 4] = s1;
        state[2 + i * 4] = s2;
        state[3 + i * 4] = s3;
    }
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция, осуществляющая операцию "смешивания" столбцов матрицы сообщения (InvMixColumns)
    (путем домножения на фиксированный многочлен) для алгоритма расшифрования AES-128.
    Для преобразований используются вспомогательные функции, упрощающие умножение в конечном поле. */
static void ak_aes128_inv_mix_columns(ak_uint8 * state)
{
    int i;
    ak_uint8 s0, s1, s2, s3;
    for (i = 0; i < 4; i++)
    {
        s0 = mul_by_0e(state[0 + i * 4]) ^ mul_by_0b(state[1 + i * 4]) ^ mul_by_0d(state[2 + i * 4]) ^ mul_by_09(state[3 + i * 4]);
        s1 = mul_by_09(state[0 + i * 4]) ^ mul_by_0e(state[1 + i * 4]) ^ mul_by_0b(state[2 + i * 4]) ^ mul_by_0d(state[3 + i * 4]);
        s2 = mul_by_0d(state[0 + i * 4]) ^ mul_by_09(state[1 + i * 4]) ^ mul_by_0e(state[2 + i * 4]) ^ mul_by_0b(state[3 + i * 4]);
        s3 = mul_by_0b(state[0 + i * 4]) ^ mul_by_0d(state[1 + i * 4]) ^ mul_by_09(state[2 + i * 4]) ^ mul_by_0e(state[3 + i * 4]);

        state[0 + i * 4] = s0;
        state[1 + i * 4] = s1;
        state[2 + i * 4] = s2;
        state[3 + i * 4] = s3;
    }
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция освобождает память, занимаемую раундовыми ключами.                              */
/* ----------------------------------------------------------------------------------------------- */
static int ak_aes128_delete_keys(ak_skey skey)
{
    int error = ak_error_ok;

     /* выполняем стандартные проверки */
    if(skey == NULL) return ak_error_message(ak_error_null_pointer,
                                                     __func__ , "using a null pointer to secret key");
    if(skey->data != NULL)
    {
         /* теперь очистка и освобождение памяти */
        if((error = ak_ptr_wipe(skey->data, sizeof(ak_aes128_expanded_keys),
                                                                   &skey->generator)) != ak_error_ok)
        {
            ak_error_message(error, __func__, "incorrect wiping an internal data");
            memset(skey->data, 0, sizeof( ak_aes128_expanded_keys));
        }
        free(skey->data);
        skey->data = NULL;
    }
    return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция релизует развертку ключей (KeyExpansion) для алгоритма AES-128.                 */
/* ----------------------------------------------------------------------------------------------- */
static int ak_aes128_schedule_keys(ak_skey skey)
{
    /* выполняем стандартные проверки */
    if(skey == NULL) return ak_error_message(ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key");
    if(skey->key_size != 16) return ak_error_message(ak_error_null_pointer, __func__ ,
                                                              "unsupported length of secret key");
    /* проверяем целостность ключа */
    if(skey->check_icode( skey ) != ak_true) return ak_error_message(ak_error_wrong_key_icode,
                                                __func__ , "using key with wrong integrity code");
    /* удаляем былое */
    if(skey->data != NULL) ak_aes128_delete_keys(skey);

    /* далее, по-возможности, выделяем выравненную память */
    if((skey->data = ak_aligned_malloc(sizeof(ak_aes128_expanded_keys))) == NULL)
        return ak_error_message(ak_error_out_of_memory, __func__ ,
                                                             "wrong allocation of internal data");
    /* получаем указатель на область памяти */
    ak_uint8 * key_schedule = (ak_uint8 *) skey->data;

    /* далее выполняем алгоритм развертки ключей (KeyExpansion) */
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            key_schedule[j + 4 * i] = skey->key[j + 4 * i];
        }
    }

    ak_uint8 tmp[4];
    ak_uint8 tmp2;

    for (i = 4; i < 44; i++)
    {
        if (i % 4 == 0)
        {
            /* преобразование RotWord */
            tmp[0] = key_schedule[1 + (i - 1) * 4];
            tmp[1] = key_schedule[2 + (i - 1) * 4];
            tmp[2] = key_schedule[3 + (i - 1) * 4];
            tmp[3] = key_schedule[0 + (i - 1) * 4];

            /* преобразование SubWord */
            for (j = 0; j < 4; j++)
            {
                tmp[j] = SBOX[16 * (tmp[j] / 0x10) + tmp[j] % 0x10];
            }

            for (j = 0; j < 4; j++)
            {
                tmp2 = (key_schedule[j + (i - 4) * 4]) ^ (tmp[j]) ^ (RCON[j][i / 4 - 1]);
                key_schedule[j + i  * 4] = tmp2;
            }
        }
        else
        {
            for (j = 0; j < 4; j++)
            {
                tmp2 = (key_schedule[j + (i - 4) * 4]) ^ (key_schedule[j + (i - 1) * 4]);
                key_schedule[j + i * 4] = tmp2;
            }
        }
    }

    return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция релизует алгоритм зашифрования одного блока информации
   шифром AES-128 (FIPS 197).                                                                      */
/* ----------------------------------------------------------------------------------------------- */
static void ak_aes128_encrypt(ak_skey skey, ak_pointer in, ak_pointer out)
{
    ak_uint8 * input = (ak_uint8 *) in;
    ak_uint8 * output = (ak_uint8 *) out;

    ak_uint8 * key_schedule = (ak_uint8 * ) skey->data;
    ak_uint8 state[4][4];

    int i, j, round = 0;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[i][j] = input[j + 4 * i];
        }
    }

    ak_aes128_add_round_key(*state, key_schedule, round);

    for (round = 1; round < 10; round++)
    {
        ak_aes128_sub_bytes(*state);
        ak_aes128_shift_rows(*state);
        ak_aes128_mix_columns(*state);
        ak_aes128_add_round_key(*state, key_schedule, round);
    }

    ak_aes128_sub_bytes(*state);
    ak_aes128_shift_rows(*state);
    ak_aes128_add_round_key(*state, key_schedule, round);

    for (i = 0; i < 16; i++)
    {
        output[i] = state[i / 4][i % 4];
    }
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция релизует алгоритм расшифрования одного блока информации
   шифром AES-128 (FIPS 197).                                                                      */
/* ----------------------------------------------------------------------------------------------- */
static void ak_aes128_decrypt(ak_skey skey, ak_pointer in, ak_pointer out)
{
    ak_uint8 * input = (ak_uint8 *) in;
    ak_uint8 * output = (ak_uint8 *) out;

    ak_uint8 * key_schedule = (ak_uint8 * ) skey->data;
    ak_uint8 state[4][4];

    int i, j, round = 10;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[i][j] = input[j + 4 * i];
        }
    }

    ak_aes128_add_round_key(*state, key_schedule, 10);

    for (round = 9; round > 0; round--)
    {
        ak_aes128_inv_shift_rows(*state);
        ak_aes128_inv_sub_bytes(*state);
        ak_aes128_add_round_key(*state, key_schedule, round);
        ak_aes128_inv_mix_columns(*state);
    }

    ak_aes128_inv_shift_rows(*state);
    ak_aes128_inv_sub_bytes(*state);
    ak_aes128_add_round_key(*state, key_schedule, round);

    for (i = 0; i < 16; i++)
    {
        output[i] = state[i / 4][i % 4];
    }
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Cпециальная функция маскирования, которая ничего не делает, так как в AES-128 не нужно
 *  маскирование. Всегда возвращает OK.                                                            */
/* ----------------------------------------------------------------------------------------------- */
static int ak_skey_set_special_aes128_mask(ak_skey skey)
{
    if(((skey->flags)&ak_key_flag_set_mask ) == 0)
    {
        skey->flags |= ak_key_flag_set_mask;
    }
    return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Cпециальная функция демаскирования, которая ничего не делает, так как в AES-128 не нужно
 *  маскирование. Всегда возвращает OK.                                                            */
/* ----------------------------------------------------------------------------------------------- */
static int ak_skey_set_special_aes128_unmask(ak_skey skey)
{
    if(((skey->flags)&ak_key_flag_set_mask) == 0)
    {
        return ak_error_ok;
    }
    skey->flags ^= ak_key_flag_set_mask;
    return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция инициализации struct bckey для AES128                                           */
/* ----------------------------------------------------------------------------------------------- */
int ak_bckey_create_aes128(ak_bckey bkey)
{
    int error = ak_error_ok, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability");

    if(bkey == NULL ) return ak_error_message(ak_error_null_pointer, __func__,
                                               "using null pointer to block cipher key context");
    /* создаем ключ алгоритма шифрования и определяем его методы */
    if((error = ak_bckey_create(bkey, 16, 16 )) != ak_error_ok )
        return ak_error_message(error, __func__, "wrong initalization of block cipher key context");

    bkey->schedule_keys = ak_aes128_schedule_keys;
    bkey->delete_keys = ak_aes128_delete_keys;
    bkey->encrypt = ak_aes128_encrypt;
    bkey->decrypt = ak_aes128_decrypt;

    // установим свои специальные функции маскирования и демаскирования
    bkey->key.set_mask = ak_skey_set_special_aes128_mask;
    bkey->key.unmask = ak_skey_set_special_aes128_unmask;
    return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция тестирования AES128                                                             */
/* ----------------------------------------------------------------------------------------------- */
bool_t ak_libakrypt_test_aes128(void)
{
    ak_uint8 for_enc[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    ak_uint8 key_enc[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    ak_uint8 out_enc[16];

    struct bckey key;
    if (ak_bckey_create_aes128(&key) != ak_error_ok)
    {
        printf("Ошибка ak_bckey_create_aes128\n");
        return ak_false;
    }

    if (ak_bckey_set_key(&key, key_enc, 16) != ak_error_ok)
    {
        printf("Ошибка ak_bckey_set_key\n");
        return ak_false;
    }

    if (ak_bckey_encrypt_ecb(&key, for_enc, out_enc, 16) != ak_error_ok)
    {
        printf("Ошибка ak_bckey_encrypt_ecb\n");
        return ak_false;
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
        return ak_false;
    }
    if (ak_bckey_decrypt_ecb(&key, for_dec, out_dec, 16 ) != ak_error_ok)
    {
        printf("Ошибка ak_bckey_decrypt_ecb\n");
        return ak_false;
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

    return ak_true;
}


 
