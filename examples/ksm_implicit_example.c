/* ksm_implicit_example.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfSSL. If not, see <http://www.gnu.org/licenses/>.
 */

/*!
    \file examples/ksm_implicit_example.c
    \brief Example demonstrating wolfKSM fully implicit key management

    This example shows how to use wolfKSM's fully implicit API where
    applications NEVER see or manage keys directly. Just specify the
    algorithm/curve and wolfKSM handles everything transparently.

    Compile:
        gcc -o ksm_implicit_example ksm_implicit_example.c \
            -lwolfssl -lwolfksm -I/usr/local/include

    Run:
        ./ksm_implicit_example
*/

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_WOLFKSM
#ifdef WOLF_CRYPTO_CB

#include <wolfssl/wolfcrypt/ksm_cryptocb.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    int rc;
    byte hash[WC_SHA256_DIGEST_SIZE];
    byte sig[ECC_MAX_SIG_SIZE];
    word32 sigLen = sizeof(sig);
    byte peerPub[ECC_MAXSIZE * 2 + 1];  /* Simulated peer public key */
    word32 peerLen = 65;  /* X9.63 format for P-256: 0x04 + 32 + 32 */
    byte secret[ECC_MAXSIZE];
    word32 secretLen = sizeof(secret);

    printf("=================================================\n");
    printf("wolfKSM Fully Implicit Key Management Example\n");
    printf("=================================================\n\n");

    /* Enable wolfSSL logging to see what's happening */
    wolfSSL_Debugging_ON();

    printf("Step 1: Register wolfKSM crypto callback\n");
    printf("-----------------------------------------\n");
    rc = wolfKSM_SetCryptoDevCb(NULL);
    if (rc != 0) {
        printf("ERROR: wolfKSM_SetCryptoDevCb failed: %d\n", rc);
        return rc;
    }
    printf("✓ wolfKSM crypto callback registered\n\n");

    /* Create some test data */
    XMEMSET(hash, 0x42, sizeof(hash));  /* Dummy hash */
    XMEMSET(peerPub, 0x04, 1);           /* X9.63 uncompressed format */
    XMEMSET(peerPub + 1, 0x55, 64);      /* Dummy peer public key */

    printf("Step 2: FULLY IMPLICIT ECC Sign (P-256)\n");
    printf("-----------------------------------------\n");
    printf("Notice: NO key management required!\n");
    printf("Just specify the curve and wolfKSM handles everything.\n\n");

    rc = wolfKSM_EccSignHash(hash, sizeof(hash), sig, &sigLen, ECC_SECP256R1);
    if (rc != 0) {
        printf("ERROR: wolfKSM_EccSignHash failed: %d\n", rc);
        return rc;
    }
    printf("✓ Signature created: %u bytes\n", sigLen);
    printf("  Private key NEVER exposed to application!\n\n");

    printf("Step 3: FULLY IMPLICIT ECDH (P-256)\n");
    printf("-----------------------------------------\n");
    printf("Again, no key management - just provide peer's public key.\n\n");

    rc = wolfKSM_EccDhAgree(peerPub, peerLen, secret, &secretLen, ECC_SECP256R1);
    if (rc != 0) {
        printf("ERROR: wolfKSM_EccDhAgree failed: %d\n", rc);
        return rc;
    }
    printf("✓ Shared secret computed: %u bytes\n", secretLen);
    printf("  Private key NEVER exposed to application!\n\n");

    printf("Step 4: Set explicit policy for P-384\n");
    printf("-----------------------------------------\n");
    printf("Pre-generate keys for specific curves if desired.\n\n");

    rc = wolfKSM_SetPolicy(ECC_SECP384R1, 1);
    if (rc != 0) {
        printf("ERROR: wolfKSM_SetPolicy failed: %d\n", rc);
        return rc;
    }
    printf("✓ Policy enabled for P-384 curve\n");
    printf("  Key generated and stored securely in KSM\n\n");

    printf("Step 5: Use P-384 implicitly\n");
    printf("-----------------------------------------\n");

    sigLen = sizeof(sig);
    rc = wolfKSM_EccSignHash(hash, sizeof(hash), sig, &sigLen, ECC_SECP384R1);
    if (rc != 0) {
        printf("ERROR: wolfKSM_EccSignHash (P-384) failed: %d\n", rc);
        return rc;
    }
    printf("✓ P-384 signature created: %u bytes\n", sigLen);
    printf("  Used pre-generated key from policy\n\n");

    printf("Step 6: Cleanup\n");
    printf("-----------------------------------------\n");

    rc = wolfKSM_ClearCryptoDevCb(WOLFKSM_DEVID);
    if (rc != 0) {
        printf("ERROR: wolfKSM_ClearCryptoDevCb failed: %d\n", rc);
        return rc;
    }
    printf("✓ wolfKSM shutdown complete\n\n");

    printf("=================================================\n");
    printf("SUCCESS: All operations completed!\n");
    printf("=================================================\n");
    printf("\nKey Takeaway:\n");
    printf("-------------\n");
    printf("Applications NEVER see private keys with wolfKSM.\n");
    printf("Just specify what you need (algorithm/curve) and\n");
    printf("wolfKSM handles key generation, storage, and crypto\n");
    printf("operations completely transparently.\n\n");

    return 0;
}

#else
int main(void)
{
    printf("ERROR: This example requires WOLF_CRYPTO_CB\n");
    printf("Rebuild wolfSSL with --enable-cryptocb --enable-ksm\n");
    return 1;
}
#endif /* WOLF_CRYPTO_CB */

#else
int main(void)
{
    printf("ERROR: This example requires HAVE_WOLFKSM\n");
    printf("Rebuild wolfSSL with --enable-ksm\n");
    return 1;
}
#endif /* HAVE_WOLFKSM */
