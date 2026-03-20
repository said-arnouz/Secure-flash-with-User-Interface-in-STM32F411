/*
 * uECC.c
 *
 *  Created on: Mar 5, 2026
 *      Author: HP
 */

#include "uECC.h"
/* ================= VERIFY SIGNATURE ================= */
uint8_t Boot_VerifySignature(uint32_t app_address, uint32_t app_size, const uint8_t *signature)
{
    /* --- Step 1: SHA-256 of flashed app in-place --- */
    uint8_t digest[32];
    size_t  digest_len = 0;

    cmox_sha256_handle_t sha_handle;
    cmox_hash_handle_t  *hash = cmox_sha256_construct(&sha_handle);

    if (hash == NULL)                                          return 0;
    if (cmox_hash_init(hash)           != CMOX_HASH_SUCCESS)  return 0;
    if (cmox_hash_setTagLen(hash, 32U) != CMOX_HASH_SUCCESS)  return 0;

    /* Feed flash content directly — no copy needed, flash is memory-mapped */
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

    /* --- Step 2: ECDSA P-256 verify --- */
    /* Static working buffer — no heap needed */
    static uint8_t ecc_membuf[CMOX_ECC_MEMBUF_SIZE];

    cmox_ecc_handle_t ecc_ctx;
    cmox_ecc_construct(&ecc_ctx, CMOX_MATH_FUNCS_SMALL,
                       ecc_membuf, sizeof(ecc_membuf));

    uint32_t          fault_check = 0;
    cmox_ecc_retval_t rv;

    rv = cmox_ecdsa_verify(
        &ecc_ctx,
        CMOX_ECC_SECP256R1_LOWMEM,  /* P-256 curve, low RAM usage */
        PUBLIC_KEY,   64U,          /* uncompressed X || Y        */
        digest,       32U,          /* SHA-256 of flashed app     */
        signature,    64U,          /* raw R || S from UART       */
        &fault_check
    );

    cmox_ecc_cleanup(&ecc_ctx);

    /* Both rv AND fault_check must equal AUTH_SUCCESS — double check against fault injection */
    if ((rv == CMOX_ECC_AUTH_SUCCESS) && (fault_check == CMOX_ECC_AUTH_SUCCESS))
        return 1;

    return 0;
}
