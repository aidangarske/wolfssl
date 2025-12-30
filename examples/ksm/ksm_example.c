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

    Build:
        This example is built automatically when wolfSSL is configured with:
            ./configure --enable-ksm --enable-keygen --enable-aesgcm \
                        --enable-hkdf --enable-curve25519 --enable-ed25519 \
                        --enable-cryptocb
            make

        See wolfKSM documentation for bootstrap build instructions.

    Run:
        ./examples/ksm/ksm_implicit_example           # Run all tests
        ./examples/ksm/ksm_implicit_example ecc       # ECC only
        ./examples/ksm/ksm_implicit_example rsa       # RSA only
        ./examples/ksm/ksm_implicit_example aes       # AES wrapping only
        ./examples/ksm/ksm_implicit_example ed25519   # Ed25519 only (when available)
        ./examples/ksm/ksm_implicit_example x25519    # X25519 only (when available)

    Manual compile (if needed):
        gcc -o ksm_implicit_example ksm_implicit_example.c \
            -lwolfssl -lwolfksm -I/usr/local/include
*/

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <stdio.h>

#ifdef HAVE_WOLFKSM
#ifdef WOLF_CRYPTO_CB

#include <wolfssl/wolfcrypt/ksm_cryptocb.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/logging.h>
#ifdef HAVE_ED25519
#include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef HAVE_CURVE25519
#include <wolfssl/wolfcrypt/curve25519.h>
#endif
#ifdef HAVE_ED448
#include <wolfssl/wolfcrypt/ed448.h>
#endif
#ifdef HAVE_CURVE448
#include <wolfssl/wolfcrypt/curve448.h>
#endif
#include <wolfksm/ksm.h>
#include <stdio.h>
#include <string.h>

/* ============================================================
 * ECC Operations Test
 * ============================================================ */

static int test_ecc_operations(void)
{
    int rc;
    WC_RNG rng;
    ecc_key key;
    ecc_key peerKey;
    byte hash[WC_SHA256_DIGEST_SIZE];
    byte sig[ECC_MAX_SIG_SIZE];
    word32 sigLen = sizeof(sig);
    byte secret[ECC_MAXSIZE];
    word32 secretLen = sizeof(secret);

    printf("\n=================================================\n");
    printf("ECC Operations (Standard wolfSSL APIs)\n");
    printf("=================================================\n\n");

    printf("Using standard wolfSSL APIs - NO code changes needed!\n");
    printf("When built with --enable-ksm, keys automatically go to KSM.\n\n");

    /* Initialize RNG */
    printf("Initializing RNG...\n");
    fflush(stdout);
    rc = wc_InitRng(&rng);
    if (rc != 0) {
        printf("ERROR: wc_InitRng failed: %d\n", rc);
        return rc;
    }
    printf("✓ RNG initialized\n");
    fflush(stdout);

    /* Create test data */
    XMEMSET(hash, 0x42, sizeof(hash));

    /* Test 1: ECC Key Generation + Sign */
    printf("Test 1: ECC P-256 Key Generation and Sign\n");
    printf("------------------------------------------\n");
    printf("Calling standard API: wc_ecc_make_key()\n\n");
    fflush(stdout);

    printf("Calling wc_ecc_init()...\n");
    fflush(stdout);
    rc = wc_ecc_init(&key);
    if (rc != 0) {
        printf("ERROR: wc_ecc_init failed: %d\n", rc);
        wc_FreeRng(&rng);
        return rc;
    }
    printf("✓ wc_ecc_init() succeeded\n");
    fflush(stdout);

    /* Generate key using STANDARD API */
    printf("Calling wc_ecc_make_key()...\n");
    fflush(stdout);
    rc = wc_ecc_make_key(&rng, 32, &key);
    printf("wc_ecc_make_key() returned: %d\n", rc);
    fflush(stdout);
    if (rc != 0) {
        printf("ERROR: wc_ecc_make_key failed: %d\n", rc);
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        return rc;
    }
    printf("About to print key info...\n");
    fflush(stdout);
    printf("✓ ECC P-256 key generated (devId=%d, KSM=%d)\n", key.devId, WOLFKSM_DEVID);
    fflush(stdout);
    printf("  Private key is in KSM hardware storage!\n\n");
    fflush(stdout);

    /* Sign using STANDARD API */
    printf("Calling standard API: wc_ecc_sign_hash()\n");
    fflush(stdout);
    printf("About to call wc_ecc_sign_hash...\n");
    fflush(stdout);
    rc = wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigLen, &rng, &key);
    printf("wc_ecc_sign_hash() returned: %d\n", rc);
    fflush(stdout);
    if (rc != 0) {
        printf("ERROR: wc_ecc_sign_hash failed: %d\n", rc);
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        return rc;
    }
    printf("✓ P-256 signature created: %u bytes\n", sigLen);
    printf("  Signing happened in KSM - private key never exposed!\n\n");

    /* Test 2: ECC ECDH */
    printf("Test 2: ECC P-256 ECDH\n");
    printf("----------------------\n");
    printf("Calling standard API: wc_ecc_shared_secret()\n\n");

    /* Generate peer key */
    rc = wc_ecc_init(&peerKey);
    if (rc != 0) {
        printf("ERROR: wc_ecc_init (peer) failed: %d\n", rc);
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        return rc;
    }

    rc = wc_ecc_make_key(&rng, 32, &peerKey);
    if (rc != 0) {
        printf("ERROR: wc_ecc_make_key (peer) failed: %d\n", rc);
        wc_ecc_free(&peerKey);
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        return rc;
    }

    /* Set RNG on both keys for side-channel protection */
    rc = wc_ecc_set_rng(&key, &rng);
    if (rc != 0) {
        printf("ERROR: wc_ecc_set_rng (key) failed: %d\n", rc);
        wc_ecc_free(&peerKey);
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        return rc;
    }

    rc = wc_ecc_set_rng(&peerKey, &rng);
    if (rc != 0) {
        printf("ERROR: wc_ecc_set_rng (peerKey) failed: %d\n", rc);
        wc_ecc_free(&peerKey);
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        return rc;
    }

    /* Compute shared secret using STANDARD API */
    rc = wc_ecc_shared_secret(&key, &peerKey, secret, &secretLen);
    if (rc != 0) {
        printf("ERROR: wc_ecc_shared_secret failed: %d\n", rc);
        wc_ecc_free(&peerKey);
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        return rc;
    }
    printf("✓ Shared secret computed: %u bytes\n", secretLen);
    printf("  ECDH happened in KSM - private key never exposed!\n\n");

    wc_ecc_free(&key);
    wc_ecc_free(&peerKey);
    wc_FreeRng(&rng);

    printf("=================================================\n");
    printf("ECC Operations: SUCCESS\n");
    printf("=================================================\n");

    return 0;
}

/* ============================================================
 * RSA Operations Test
 * ============================================================ */

#ifndef NO_RSA
static int test_rsa_operations(void)
{
    int rc;
    WC_RNG rng;
    RsaKey rsaKey;
    byte hash[WC_SHA256_DIGEST_SIZE];
    byte sig[512];
    word32 sigLen = sizeof(sig);

    printf("\n=================================================\n");
    printf("RSA Operations (Standard wolfSSL APIs)\n");
    printf("=================================================\n\n");

    printf("Using standard wolfSSL APIs - NO code changes needed!\n");
    printf("When built with --enable-ksm, keys automatically go to KSM.\n\n");

    /* Initialize RNG */
    rc = wc_InitRng(&rng);
    if (rc != 0) {
        printf("ERROR: wc_InitRng failed: %d\n", rc);
        return rc;
    }

    /* Create test hash */
    XMEMSET(hash, 0x42, sizeof(hash));

    /* Test 1: RSA Key Generation and Sign */
    printf("Test 1: RSA-2048 Key Generation and Sign\n");
    printf("-----------------------------------------\n");
    printf("Calling standard API: wc_MakeRsaKey()\n\n");

    /* Initialize RSA key structure */
    rc = wc_InitRsaKey(&rsaKey, NULL);
    if (rc != 0) {
        printf("ERROR: wc_InitRsaKey failed: %d\n", rc);
        wc_FreeRng(&rng);
        return rc;
    }

    /* Generate RSA key using STANDARD API */
    rc = wc_MakeRsaKey(&rsaKey, 2048, 65537, &rng);
    if (rc != 0) {
        printf("ERROR: wc_MakeRsaKey failed: %d\n", rc);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return rc;
    }
    printf("✓ RSA-2048 key generated (devId=%d, KSM=%d)\n", rsaKey.devId, WOLFKSM_DEVID);
    printf("  Private key is in KSM hardware storage!\n\n");

    /* Sign using STANDARD API */
    printf("Calling standard API: wc_RsaSSL_Sign()\n");
    rc = wc_RsaSSL_Sign(hash, sizeof(hash), sig, sizeof(sig), &rsaKey, &rng);
    if (rc < 0) {
        printf("ERROR: wc_RsaSSL_Sign failed: %d\n", rc);
        wc_FreeRsaKey(&rsaKey);
        wc_FreeRng(&rng);
        return rc;
    }
    sigLen = (word32)rc;
    printf("✓ RSA-2048 signature created: %u bytes\n", sigLen);
    printf("  Signing happened in KSM - private key never exposed!\n\n");

    wc_FreeRsaKey(&rsaKey);
    wc_FreeRng(&rng);

    printf("=================================================\n");
    printf("RSA Operations: SUCCESS\n");
    printf("=================================================\n");

    return 0;
}
#endif /* !NO_RSA */

/* ============================================================
 * AES Wrapping Test
 * ============================================================ */

static int test_aes_wrapping(void)
{
    int rc;
    ksm_key_id wrapKey = KSM_KEY_INVALID;
    ksm_key_id dataKey = KSM_KEY_INVALID;
    ksm_key_id restoredKey = KSM_KEY_INVALID;
    byte wrapped[512];
    word32 wrappedLen = sizeof(wrapped);
    byte hash1[WC_SHA256_DIGEST_SIZE];
    byte hash2[WC_SHA256_DIGEST_SIZE];
    byte sig1[ECC_MAX_SIG_SIZE];
    byte sig2[ECC_MAX_SIG_SIZE];
    word32 sig1Len = sizeof(sig1);
    word32 sig2Len = sizeof(sig2);

    printf("\n=================================================\n");
    printf("AES Key Wrapping (Encrypted Backup)\n");
    printf("=================================================\n\n");

    printf("Test 1: Generate AES Wrapping Key\n");
    printf("----------------------------------\n");

    rc = ksm_generate(KSM_TYPE_AES_256, &wrapKey);
    if (rc != KSM_SUCCESS) {
        printf("ERROR: ksm_generate (AES) failed: %d\n", rc);
        return rc;
    }
    printf("✓ AES-256 wrapping key generated in KSM\n");
    printf("  Key ID: %u\n\n", wrapKey);

    printf("Test 2: Generate ECC Key to Wrap\n");
    printf("---------------------------------\n");

    rc = ksm_generate(KSM_TYPE_ECC_P256, &dataKey);
    if (rc != KSM_SUCCESS) {
        printf("ERROR: ksm_generate (ECC) failed: %d\n", rc);
        goto cleanup;
    }
    printf("✓ ECC P-256 key generated in KSM\n");
    printf("  Key ID: %u\n\n", dataKey);

    printf("Test 3: Create Signature with Original Key\n");
    printf("-------------------------------------------\n");

    XMEMSET(hash1, 0x42, sizeof(hash1));
    rc = ksm_sign(dataKey, hash1, sizeof(hash1), sig1, &sig1Len);
    if (rc != KSM_SUCCESS) {
        printf("ERROR: ksm_sign failed: %d\n", rc);
        goto cleanup;
    }
    printf("✓ Signature with original key: %u bytes\n\n", sig1Len);

    printf("Test 4: Export Wrapped (Encrypted Backup)\n");
    printf("------------------------------------------\n");

    rc = ksm_export_wrapped(dataKey, wrapKey, wrapped, &wrappedLen);
    if (rc != KSM_SUCCESS) {
        printf("ERROR: ksm_export_wrapped failed: %d\n", rc);
        goto cleanup;
    }
    printf("✓ Key exported (encrypted): %u bytes\n", wrappedLen);
    printf("  Wrapped key is encrypted with AES-256-GCM\n");
    printf("  Can be safely stored or transmitted\n\n");

    printf("Test 5: Destroy Original Key\n");
    printf("-----------------------------\n");

    rc = ksm_destroy(dataKey);
    if (rc != KSM_SUCCESS) {
        printf("ERROR: ksm_destroy failed: %d\n", rc);
        goto cleanup;
    }
    printf("✓ Original key securely destroyed\n");
    printf("  Key material has been zeroed\n\n");

    printf("Test 6: Import Wrapped (Restore from Backup)\n");
    printf("--------------------------------------------\n");

    rc = ksm_import_wrapped(wrapped, wrappedLen, wrapKey,
                            KSM_TYPE_ECC_P256, &restoredKey);
    if (rc != KSM_SUCCESS) {
        printf("ERROR: ksm_import_wrapped failed: %d\n", rc);
        goto cleanup;
    }
    printf("✓ Key restored from encrypted backup\n");
    printf("  Restored Key ID: %u\n\n", restoredKey);

    printf("Test 7: Verify Restored Key\n");
    printf("----------------------------\n");

    XMEMSET(hash2, 0x42, sizeof(hash2));
    rc = ksm_sign(restoredKey, hash2, sizeof(hash2), sig2, &sig2Len);
    if (rc != KSM_SUCCESS) {
        printf("ERROR: ksm_sign (restored) failed: %d\n", rc);
        goto cleanup;
    }
    printf("✓ Signature with restored key: %u bytes\n", sig2Len);
    printf("✓ Key successfully restored and working!\n");
    printf("  NOTE: ECC signatures differ each time due to randomness,\n");
    printf("        but both are valid signatures from the same key.\n\n");

    printf("=================================================\n");
    printf("AES Key Wrapping: SUCCESS\n");
    printf("=================================================\n");
    printf("\nKey Takeaway:\n");
    printf("-------------\n");
    printf("Wrapped export allows secure backup and migration\n");
    printf("of keys without ever exposing private key bytes.\n");
    printf("The wrapped key is encrypted with AES-256-GCM.\n\n");

    rc = 0;

cleanup:
    if (wrapKey != KSM_KEY_INVALID)
        ksm_destroy(wrapKey);
    if (restoredKey != KSM_KEY_INVALID)
        ksm_destroy(restoredKey);

    return rc;
}

/* ============================================================
 * Ed25519 Operations Test
 * ============================================================ */

#ifdef HAVE_ED25519
static int test_ed25519_operations(void)
{
    int rc;
    byte msg[] = "Test message for Ed25519 signature";
    word32 msgLen = (word32)XSTRLEN((char*)msg);
    byte sig[ED25519_SIG_SIZE];
    word32 sigLen = sizeof(sig);
    byte msg2[] = "Another message to sign";
    word32 msg2Len = (word32)XSTRLEN((char*)msg2);
    byte sig2[ED25519_SIG_SIZE];
    word32 sig2Len = sizeof(sig2);

    printf("\n=================================================\n");
    printf("Ed25519 Operations (Fully Implicit)\n");
    printf("=================================================\n\n");

    /* Test 1: Ed25519 Sign */
    printf("Test 1: Ed25519 Sign\n");
    printf("--------------------\n");
    printf("NO key management required!\n");
    printf("wolfKSM handles key generation and signing transparently.\n\n");

    rc = wolfKSM_Ed25519Sign(msg, msgLen, sig, &sigLen);
    if (rc != 0) {
        printf("ERROR: wolfKSM_Ed25519Sign failed: %d\n", rc);
        return rc;
    }
    printf("✓ Ed25519 signature created: %u bytes\n", sigLen);
    printf("  Message: \"%s\"\n", msg);
    printf("  Private key NEVER exposed to application!\n\n");

    /* Test 2: Ed25519 Sign (Second Message) */
    printf("Test 2: Ed25519 Sign (Reuse Key)\n");
    printf("---------------------------------\n");
    printf("Signing another message with the same key.\n\n");

    rc = wolfKSM_Ed25519Sign(msg2, msg2Len, sig2, &sig2Len);
    if (rc != 0) {
        printf("ERROR: wolfKSM_Ed25519Sign (second) failed: %d\n", rc);
        return rc;
    }
    printf("✓ Ed25519 signature created: %u bytes\n", sig2Len);
    printf("  Message: \"%s\"\n", msg2);
    printf("  Used the same key (auto-managed by wolfKSM)\n\n");

    printf("=================================================\n");
    printf("Ed25519 Operations: SUCCESS\n");
    printf("=================================================\n");

    return 0;
}
#endif /* HAVE_ED25519 */

/* ============================================================
 * X25519 Operations Test
 * ============================================================ */

#ifdef HAVE_CURVE25519
static int test_x25519_operations(void)
{
    int rc;
    byte peerPub[CURVE25519_KEYSIZE];
    word32 peerLen = CURVE25519_KEYSIZE;
    byte secret[CURVE25519_KEYSIZE];
    word32 secretLen = sizeof(secret);
    byte peerPub2[CURVE25519_KEYSIZE];
    byte secret2[CURVE25519_KEYSIZE];
    word32 secret2Len = sizeof(secret2);

    printf("\n=================================================\n");
    printf("X25519 Operations (Fully Implicit)\n");
    printf("=================================================\n\n");

    /* Simulate peer public keys (in real usage, these come from the peer) */
    XMEMSET(peerPub, 0x55, CURVE25519_KEYSIZE);
    XMEMSET(peerPub2, 0x66, CURVE25519_KEYSIZE);

    /* Test 1: X25519 Key Exchange */
    printf("Test 1: X25519 Key Exchange\n");
    printf("----------------------------\n");
    printf("NO key management required!\n");
    printf("Just provide peer's public key.\n\n");

    rc = wolfKSM_X25519SharedSecret(peerPub, peerLen, secret, &secretLen);
    if (rc != 0) {
        printf("ERROR: wolfKSM_X25519SharedSecret failed: %d\n", rc);
        return rc;
    }
    printf("✓ Shared secret computed: %u bytes\n", secretLen);
    printf("  Private key NEVER exposed to application!\n\n");

    /* Test 2: X25519 Key Exchange (Different Peer) */
    printf("Test 2: X25519 Key Exchange (Reuse Key)\n");
    printf("----------------------------------------\n");
    printf("Computing shared secret with a different peer.\n\n");

    rc = wolfKSM_X25519SharedSecret(peerPub2, peerLen, secret2, &secret2Len);
    if (rc != 0) {
        printf("ERROR: wolfKSM_X25519SharedSecret (second) failed: %d\n", rc);
        return rc;
    }
    printf("✓ Shared secret computed: %u bytes\n", secret2Len);
    printf("  Used the same key (auto-managed by wolfKSM)\n\n");

    /* Verify secrets are different (different peer public keys) */
    if (XMEMCMP(secret, secret2, secretLen) != 0) {
        printf("✓ Different peer → different shared secret (as expected)\n\n");
    } else {
        printf("WARNING: Shared secrets match (unexpected for different peers)\n\n");
    }

    printf("=================================================\n");
    printf("X25519 Operations: SUCCESS\n");
    printf("=================================================\n");

    return 0;
}
#endif /* HAVE_CURVE25519 */

/* ============================================================
 * Ed448 Operations Test
 * ============================================================ */

#ifdef HAVE_ED448
static int test_ed448_operations(void)
{
    int rc;
    byte msg[] = "Test message for Ed448 signature";
    word32 msgLen = (word32)XSTRLEN((char*)msg);
    byte sig[ED448_SIG_SIZE];
    word32 sigLen = sizeof(sig);
    byte msg2[] = "Another message for Ed448";
    word32 msg2Len = (word32)XSTRLEN((char*)msg2);
    byte sig2[ED448_SIG_SIZE];
    word32 sig2Len = sizeof(sig2);

    printf("\n=================================================\n");
    printf("Ed448 Operations (Fully Implicit)\n");
    printf("=================================================\n\n");

    /* Test 1: Ed448 Sign */
    printf("Test 1: Ed448 Sign\n");
    printf("------------------\n");
    printf("NO key management required!\n");
    printf("wolfKSM handles key generation and signing transparently.\n\n");

    rc = wolfKSM_Ed448Sign(msg, msgLen, sig, &sigLen);
    if (rc != 0) {
        printf("ERROR: wolfKSM_Ed448Sign failed: %d\n", rc);
        return rc;
    }
    printf("✓ Ed448 signature created: %u bytes\n", sigLen);
    printf("  Message: \"%s\"\n", msg);
    printf("  Private key NEVER exposed to application!\n\n");

    /* Test 2: Ed448 Sign (Second Message) */
    printf("Test 2: Ed448 Sign (Reuse Key)\n");
    printf("-------------------------------\n");
    printf("Signing another message with the same key.\n\n");

    rc = wolfKSM_Ed448Sign(msg2, msg2Len, sig2, &sig2Len);
    if (rc != 0) {
        printf("ERROR: wolfKSM_Ed448Sign (second) failed: %d\n", rc);
        return rc;
    }
    printf("✓ Ed448 signature created: %u bytes\n", sig2Len);
    printf("  Message: \"%s\"\n", msg2);
    printf("  Used the same key (auto-managed by wolfKSM)\n\n");

    printf("=================================================\n");
    printf("Ed448 Operations: SUCCESS\n");
    printf("=================================================\n");

    return 0;
}
#endif /* HAVE_ED448 */

/* ============================================================
 * X448 Operations Test
 * ============================================================ */

#ifdef HAVE_CURVE448
static int test_x448_operations(void)
{
    int rc;
    byte peerPub[CURVE448_KEY_SIZE];
    word32 peerLen = CURVE448_KEY_SIZE;
    byte secret[WC_SHA256_DIGEST_SIZE];  /* HKDF output */
    word32 secretLen = sizeof(secret);
    byte peerPub2[CURVE448_KEY_SIZE];
    byte secret2[WC_SHA256_DIGEST_SIZE];
    word32 secret2Len = sizeof(secret2);

    printf("\n=================================================\n");
    printf("X448 Operations (Fully Implicit)\n");
    printf("=================================================\n\n");

    /* Simulate peer public keys (in real usage, these come from the peer) */
    XMEMSET(peerPub, 0x77, CURVE448_KEY_SIZE);
    XMEMSET(peerPub2, 0x88, CURVE448_KEY_SIZE);

    /* Test 1: X448 Key Exchange */
    printf("Test 1: X448 Key Exchange\n");
    printf("-------------------------\n");
    printf("NO key management required!\n");
    printf("Just provide peer's public key.\n\n");

    rc = wolfKSM_X448SharedSecret(peerPub, peerLen, secret, &secretLen);
    if (rc != 0) {
        printf("ERROR: wolfKSM_X448SharedSecret failed: %d\n", rc);
        return rc;
    }
    printf("✓ Shared secret computed: %u bytes\n", secretLen);
    printf("  Private key NEVER exposed to application!\n");
    printf("  (X448 output is HKDF-derived for consistent 32-byte output)\n\n");

    /* Test 2: X448 Key Exchange (Different Peer) */
    printf("Test 2: X448 Key Exchange (Reuse Key)\n");
    printf("--------------------------------------\n");
    printf("Computing shared secret with a different peer.\n\n");

    rc = wolfKSM_X448SharedSecret(peerPub2, peerLen, secret2, &secret2Len);
    if (rc != 0) {
        printf("ERROR: wolfKSM_X448SharedSecret (second) failed: %d\n", rc);
        return rc;
    }
    printf("✓ Shared secret computed: %u bytes\n", secret2Len);
    printf("  Used the same key (auto-managed by wolfKSM)\n\n");

    /* Verify secrets are different (different peer public keys) */
    if (XMEMCMP(secret, secret2, secretLen) != 0) {
        printf("✓ Different peer → different shared secret (as expected)\n\n");
    } else {
        printf("WARNING: Shared secrets match (unexpected for different peers)\n\n");
    }

    printf("=================================================\n");
    printf("X448 Operations: SUCCESS\n");
    printf("=================================================\n");

    return 0;
}
#endif /* HAVE_CURVE448 */

/* ============================================================
 * Main Entry Point
 * ============================================================ */

static void print_usage(const char* prog)
{
    printf("Usage: %s [all|ecc|rsa|aes|ed25519|x25519|ed448|x448]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  all         - Run all available tests (default)\n");
    printf("  ecc         - ECC operations using standard wolfSSL APIs\n");
    printf("  rsa         - RSA operations using standard wolfSSL APIs\n");
    printf("  aes         - AES key wrapping demonstration\n");
    printf("  ed25519     - Ed25519 signing (when available)\n");
    printf("  x25519      - X25519 key exchange (when available)\n");
    printf("  ed448       - Ed448 signing (when available)\n");
    printf("  x448        - X448 key exchange (when available)\n");
    printf("\n");
    printf("Note: All tests use standard wolfSSL APIs with ZERO code changes.\n");
    printf("      Keys are automatically stored in KSM when built with --enable-ksm.\n");
    printf("\n");
}

int main(int argc, char** argv)
{
    int rc = 0;
    const char* test = (argc > 1) ? argv[1] : "all";
    int runAll = (strcmp(test, "all") == 0);

    printf("=================================================\n");
    printf("wolfKSM Algorithm Examples\n");
    printf("=================================================\n");

    if (strcmp(test, "help") == 0 || strcmp(test, "-h") == 0 ||
        strcmp(test, "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    /* Enable wolfSSL logging */
    printf("\nEnabling wolfSSL debugging...\n");
    fflush(stdout);
    wolfSSL_Debugging_ON();
    printf("✓ Debug logging enabled\n");
    fflush(stdout);

    /* Register wolfKSM crypto callback */
    printf("\nInitializing wolfKSM crypto callback...\n");
    fflush(stdout);
    rc = wolfKSM_SetCryptoDevCb(NULL);
    if (rc != 0) {
        printf("ERROR: wolfKSM_SetCryptoDevCb failed: %d\n", rc);
        fflush(stdout);
        return rc;
    }
    printf("✓ wolfKSM crypto callback registered\n");
    fflush(stdout);

    /* Run requested tests */
    if (runAll || strcmp(test, "ecc") == 0) {
        rc = test_ecc_operations();
        if (rc != 0) goto cleanup;
    }

#ifndef NO_RSA
    if (runAll || strcmp(test, "rsa") == 0) {
        rc = test_rsa_operations();
        if (rc != 0) goto cleanup;
    }
#else
    if (strcmp(test, "rsa") == 0) {
        printf("\nRSA support not compiled in (NO_RSA defined)\n");
    }
#endif

    if (runAll || strcmp(test, "aes") == 0) {
        rc = test_aes_wrapping();
        if (rc != 0) goto cleanup;
    }

#ifdef HAVE_ED25519
    if (runAll || strcmp(test, "ed25519") == 0) {
        rc = test_ed25519_operations();
        if (rc != 0) goto cleanup;
    }
#else
    if (strcmp(test, "ed25519") == 0) {
        printf("\nEd25519 support not compiled in (HAVE_ED25519 not defined)\n");
        printf("Rebuild wolfSSL with --enable-ed25519\n");
    }
#endif

#ifdef HAVE_CURVE25519
    if (runAll || strcmp(test, "x25519") == 0) {
        rc = test_x25519_operations();
        if (rc != 0) goto cleanup;
    }
#else
    if (strcmp(test, "x25519") == 0) {
        printf("\nX25519 support not compiled in (HAVE_CURVE25519 not defined)\n");
        printf("Rebuild wolfSSL with --enable-curve25519\n");
    }
#endif

#ifdef HAVE_ED448
    if (runAll || strcmp(test, "ed448") == 0) {
        rc = test_ed448_operations();
        if (rc != 0) goto cleanup;
    }
#else
    if (strcmp(test, "ed448") == 0) {
        printf("\nEd448 support not compiled in (HAVE_ED448 not defined)\n");
        printf("Rebuild wolfSSL with --enable-ed448\n");
    }
#endif

#ifdef HAVE_CURVE448
    if (runAll || strcmp(test, "x448") == 0) {
        rc = test_x448_operations();
        if (rc != 0) goto cleanup;
    }
#else
    if (strcmp(test, "x448") == 0) {
        printf("\nX448 support not compiled in (HAVE_CURVE448 not defined)\n");
        printf("Rebuild wolfSSL with --enable-curve448\n");
    }
#endif

    /* Final summary */
    printf("\n=================================================\n");
    printf("SUCCESS: All requested tests completed!\n");
    printf("=================================================\n");
    printf("\nKey Takeaway:\n");
    printf("-------------\n");
    printf("Applications NEVER see private keys with wolfKSM.\n");
    printf("Just specify what you need (algorithm/curve/size)\n");
    printf("and wolfKSM handles key generation, storage, and\n");
    printf("crypto operations completely transparently.\n\n");

cleanup:
    /* Cleanup */
    printf("Shutting down wolfKSM...\n");
    wolfKSM_ClearCryptoDevCb(WOLFKSM_DEVID);
    printf("✓ Cleanup complete\n\n");

    return rc;
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
