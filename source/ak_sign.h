/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_sign.h                                                                                 */
/*  - содержит описание функций для работы с электронной подписью.                                 */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_SIGN_H__
#define    __AK_SIGN_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_hmac.h>
 #include <ak_curves.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Секретный ключ алгоритма выработки электронной подписи

   Может рассматриваться в качестве секретного ключа как для стандарта ГОСТ Р 34.10-2012, так и для
   предыдущей редакции ГОСТ Р 34.10-2001. Кроме того, данный контекст секретного ключа может быть
   применим для любого асимметричного криптографического механизма, использующего вычисления
   с эллиптическими кривыми.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct signkey {
 /*! \brief контекст секретного ключа */
  struct skey key;
 /*! \brief контекст функции хеширования */
  struct hash ctx;
} *ak_signkey;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста секретного ключа алгоритма ГОСТ Р 34.10-2012. */
 int ak_signkey_context_create_streebog256( ak_signkey , ak_wcurve );
/*! \brief Инициализация контекста секретного ключа алгоритма ГОСТ Р 34.10-2012. */
 int ak_signkey_context_create_streebog512( ak_signkey , ak_wcurve );
/*! \brief Инициализация контекста секретного ключа алгоритма ГОСТ Р 34.10-2001. */
 int ak_signkey_context_create_gosthash94( ak_signkey , ak_oid , ak_wcurve );
/*! \brief Уничтожение контекста секретного ключа. */
 int ak_signkey_context_destroy( ak_signkey );
/*! \brief Освобождение памяти из под контекста секретного ключа. */
 ak_pointer ak_signkey_context_delete( ak_pointer );

/*! \brief Присвоение секретному ключу электронной подписи константного (заранее заданного) значения. */
 int ak_signkey_context_set_key( ak_signkey sctx, const ak_pointer , const size_t );
/*! \brief Присвоение секретному ключу электронной подписи случайного значения. */
 int ak_signkey_context_set_key_random( ak_signkey , ak_random );
/*! \brief Присвоение секретному ключу электронной подписи значения, выработанного из пароля. */
 int ak_signkey_context_set_key_from_password( ak_signkey ,
                                 const ak_pointer , const size_t , const ak_pointer , const size_t );
/*! \brief Выработка электронной подписи для фиксированного значения случайного числа и вычисленного
    заранее значения хеш-функции. */
 void ak_signkey_context_sign_const_values( ak_signkey , ak_uint64 *, ak_pointer , ak_pointer );
/*! \brief Выработка электронной подписи для вычисленного заранее значения хеш-функции. */
 ak_buffer ak_signkey_context_sign_hash( ak_signkey , ak_pointer , size_t , ak_pointer );
/*! \brief Выработка электронной подписи для заданной области памяти. */
 ak_buffer ak_signkey_context_sign_ptr( ak_signkey , const ak_pointer , const size_t , ak_pointer );
/*! \brief Выработка электронной подписи для заданного файла. */
 ak_buffer ak_signkey_context_sign_file( ak_signkey , const char * , ak_pointer );

/*! \brief Выполнение тестовых примеров для алгоритмов выработки и проверки электронной подписи */
 ak_bool ak_signkey_test( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Открытый ключ алгоритма проверки электронной подписи ГОСТ Р 34.10-2012. */
 typedef struct verifykey {
 /*! \brief контекст функции хеширования */
  struct hash ctx;
 /*! \brief контекст эллиптической кривой */
  ak_wcurve wc;
 /*! \brief OID алгоритма проверки */
  ak_oid oid;
 /*! \brief точка кривой, являющаяся открытым ключом */
  struct wpoint qpoint;
} *ak_verifykey;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста открытого ключа алгоритма ГОСТ Р 34.10-2012. */
 int ak_verifykey_context_create_signkey( ak_verifykey , ak_signkey );
/*! \brief Уничтожение контекста открытого ключа. */
 int ak_verifykey_context_destroy( ak_verifykey );
/*! \brief Освобождение памяти из под контекста открытого ключа. */
 ak_pointer ak_verifykey_context_delete( ak_pointer );

/*! \brief Проверка электронной подписи для вычисленного заранее значения хеш-функции. */
 ak_bool ak_verifykey_context_verify_hash( ak_verifykey , const ak_pointer ,
                                                                       const size_t , ak_pointer );
/*! \brief Проверка электронной подписи для заданной области памяти. */
 ak_bool ak_verifykey_context_verify_ptr( ak_verifykey , const ak_pointer ,
                                                                       const size_t , ak_pointer );
/*! \brief Проверка электронной подписи для заданного файла. */
 ak_bool ak_verifykey_context_verify_file( ak_verifykey , const char * , ak_pointer );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_sign.h  */
/* ----------------------------------------------------------------------------------------------- */
