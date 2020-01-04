/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2020 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_asn1_keys.h                                                                            */
/*  - содержит описания функций, предназначенных для экспорта/импорта ключевой информации          */
/* ----------------------------------------------------------------------------------------------- */
#ifndef __AK_ASN1_KEYS_H__
#define __AK_ASN1_KEYS_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_asn1.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Добавление временного интервала, в ходе которого действительна ключевая информация. */
 int ak_asn1_context_add_time_validity( ak_asn1 , time_t, time_t );
/*! \brief Добавление метаданных секретного ключа. */
 int ak_asn1_context_add_skey_metadata( ak_asn1 , ak_skey );

/* ----------------------------------------------------------------------------------------------- */
         /* Функции экспорта/импорта ключевой информации с использованием формата ASN.1 */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Экспорт секретного ключа в формате ASN.1 дерева. */
 int ak_skey_context_export_to_asn1_with_password( ak_skey , ak_asn1 , const char * , const size_t );
/*! \brief Экспорт секретного ключа в файл. */
 int ak_skey_context_export_to_derfile_with_password( ak_skey, char * , const size_t ,
                                                                       const char * , const size_t );
#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_asn1_keys.h  */
/* ----------------------------------------------------------------------------------------------- */