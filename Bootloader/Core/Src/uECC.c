/**
 * @file    uECC.c
 * @brief   ECDSA P-256 signature verification for STM32 bootloader.
 *          Uses STM32 CMOX cryptographic library (SHA-256 + ECDSA P-256).
 * @author  SAID ARNOUZ
 * @date    2026
 */

#include "uECC.h"

/**
 * @brief  Verifies the ECDSA P-256 signature of the flashed application.
 * @details Two-step process:
 *          Step 1 : Compute SHA-256 digest of the flashed firmware
 *                   directly from flash (memory-mapped, no copy needed).
 *          Step 2 : Verify ECDSA P-256 signature against the digest
 *                   using the embedded public key.
 *          Double fault-injection check: both rv and fault_check
 *          must equal CMOX_ECC_AUTH_SUCCESS.
 *
 * @param  app_address : start address of the flashed application in flash.
 * @param  app_size    : size of the application in bytes (original, before compression).
 * @param  signature   : pointer to 64-byte raw ECDSA signature (R || S, big-endian).
 * @return 1 : signature valid.
 *         0 : signature invalid or crypto error.
 */
uint8_t Boot_VerifySignature(uint32_t app_address, uint32_t app_size, const uint8_t *signature)
{
    uint8_t digest[32];
    size_t  digest_len = 0;

    cmox_sha256_handle_t sha_handle;
    cmox_hash_handle_t  *hash = cmox_sha256_construct(&sha_handle);

    if (hash == NULL)                                          return 0;
    if (cmox_hash_init(hash)           != CMOX_HASH_SUCCESS)  return 0;
    if (cmox_hash_setTagLen(hash, 32U) != CMOX_HASH_SUCCESS)  return 0;

    if (cmox_hash_append(hash, (const uint8_t *)app_address, (size_t)app_size)
        != CMOX_HASH_SUCCESS)
    {
        cmox_hash_cleanup(hash);
        return 0;
    }

    if (cmox_hash_generateTag(hash, digest, &digest_len) != CMOX_HASH_SUCCESS)
    {
        cmox_hash_cleanup(hash);
        return 0;
    }
    cmox_hash_cleanup(hash);

    static uint8_t ecc_membuf[CMOX_ECC_MEMBUF_SIZE];
    cmox_ecc_handle_t ecc_ctx;
    cmox_ecc_construct(&ecc_ctx, CMOX_MATH_FUNCS_SMALL,
                       ecc_membuf, sizeof(ecc_membuf));

    uint32_t          fault_check = 0;
    cmox_ecc_retval_t rv;

    rv = cmox_ecdsa_verify(
        &ecc_ctx,
        CMOX_ECC_SECP256R1_LOWMEM,
        PUBLIC_KEY,   64U,
        digest,       32U,
        signature,    64U,
        &fault_check
    );

    cmox_ecc_cleanup(&ecc_ctx);

    if ((rv == CMOX_ECC_AUTH_SUCCESS) && (fault_check == CMOX_ECC_AUTH_SUCCESS))
        return 1;

    return 0;
}
