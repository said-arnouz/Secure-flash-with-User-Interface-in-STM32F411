/**
 * @file    lzss_aes_gcm.h
 * @brief   LZSS decompression + AES-256-GCM decryption for STM32 bootloader.
 * @author  SAID ARNOUZ
 * @date    2025
 */

#ifndef INC_LZSS_AES_GCM_H_
#define INC_LZSS_AES_GCM_H_

#include "stm32f4xx_hal.h"
/* CMOX direct API — no legacy wrapper needed */
#include "cmox_crypto.h"
#include "cmox_gcm.h"
#include "legacy_v3_aes_gcm.h"
#include "err_codes.h"

static const uint8_t AES_KEY[32] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};
/**
 * @brief   Receives encrypted+compressed chunks from UART,
 *          decrypts with AES-GCM, decompresses with LZSS,
 *          and writes the result directly to flash.
 * @param   huart         : pointer to UART handle.
 * @param   original_size : expected size of decompressed firmware.
 * @param   flash_address : starting flash address to write to.
 * @param   iv            : pointer to AES-GCM IV (12 bytes).
 * @param   tag           : pointer to AES-GCM authentication tag (16 bytes).
 * @return  1 : success — firmware written and authenticated.
 *          0 : failure — flash write error or authentication failed.
 */
uint8_t Decrypt_DecomprToFlash(UART_HandleTypeDef *huart,
                                uint32_t            original_size,
                                uint32_t            flash_address,
                                uint8_t            *iv,
                                uint8_t            *tag);

#endif /* INC_LZSS_AES_GCM_H_ */
