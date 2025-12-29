/* ksm_cryptocb.h
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
    \file wolfssl/wolfcrypt/ksm_cryptocb.h
    \brief wolfKSM integration via wolfCrypt crypto callback framework

    This file provides the bridge between wolfCrypt and wolfKSM using the
    standard crypto callback (cryptocb) framework. When HAVE_WOLFKSM is
    defined, cryptographic operations can be routed through the Key Store
    Manager, ensuring private keys never leave secure storage.
*/

#ifndef WOLF_CRYPT_KSM_CRYPTOCB_H
#define WOLF_CRYPT_KSM_CRYPTOCB_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_WOLFKSM

#ifdef WOLF_CRYPTO_CB
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfksm/ksm.h>

#ifdef __cplusplus
extern "C" {
#endif

/* wolfKSM Device ID for crypto callback registration */
#ifndef WOLFKSM_DEVID
#define WOLFKSM_DEVID 10  /* Unique device ID for KSM */
#endif

/* ============================================================
 * Crypto Callback Registration
 * ============================================================ */

/**
 * A reference crypto callback API for using wolfKSM for crypto offload.
 * This callback function is registered using wolfKSM_SetCryptoDevCb or
 * wc_CryptoCb_RegisterDevice.
 *
 * @param devId The devId used when registering the callback
 * @param info Pointer to wc_CryptoInfo structure with crypto details
 * @param ctx User context supplied when callback was registered
 *
 * @return 0 on success
 * @return CRYPTOCB_UNAVAILABLE: Fall back to software crypto
 * @return Negative on error
 */
WOLFSSL_API int wolfKSM_CryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx);

/**
 * Register the wolfKSM crypto callback.
 * Initializes wolfKSM and registers the crypto callback handler.
 *
 * @param pDevId Pointer to receive the assigned device ID (can be NULL)
 *
 * @return 0 on success, negative on error
 */
WOLFSSL_API int wolfKSM_SetCryptoDevCb(int* pDevId);

/**
 * Unregister the wolfKSM crypto callback.
 * Cleans up wolfKSM and unregisters the crypto callback.
 *
 * @param devId The device ID returned from wolfKSM_SetCryptoDevCb
 *
 * @return 0 on success, negative on error
 */
WOLFSSL_API int wolfKSM_ClearCryptoDevCb(int devId);

/* ============================================================
 * Policy-Based Key Management (Fully Implicit API)
 * ============================================================ */

/**
 * Set default policy for automatic key selection.
 * When a policy is set, wolfKSM automatically generates and manages
 * a key for the specified algorithm/curve. Applications can then use
 * implicit wrappers without managing keys.
 *
 * @param curveId Curve ID (ECC_SECP256R1, ECC_SECP384R1, etc.)
 * @param enable 1 to enable KSM for this curve, 0 to disable
 *
 * @return 0 on success, negative on error
 */
WOLFSSL_API int wolfKSM_SetPolicy(int curveId, int enable);

/**
 * Get the default key for a specific curve (if policy is set).
 * Returns a lightweight virtual key structure that triggers KSM via cryptocb.
 *
 * @param curveId Curve ID (ECC_SECP256R1, ECC_SECP384R1, etc.)
 *
 * @return Pointer to virtual key, or NULL if no policy set
 */
#ifndef NO_ECC
WOLFSSL_API ecc_key* wolfKSM_GetDefaultEccKey(int curveId);
#endif

#ifndef NO_RSA
WOLFSSL_API RsaKey* wolfKSM_GetDefaultRsaKey(int keySize);
#endif

/* ============================================================
 * Fully Implicit Crypto Operations (No Key Management!)
 * ============================================================ */

#ifndef NO_ECC
/**
 * Sign a hash using KSM-managed key (fully implicit).
 * No key management required - just specify the curve.
 *
 * @param hash Hash to sign
 * @param hashLen Hash length
 * @param sig Signature output buffer
 * @param sigLen [in/out] Buffer size, receives signature size
 * @param curveId Curve ID (ECC_SECP256R1, ECC_SECP384R1)
 *
 * @return 0 on success, negative on error
 */
WOLFSSL_API int wolfKSM_EccSignHash(const byte* hash, word32 hashLen,
                                     byte* sig, word32* sigLen,
                                     int curveId);

/**
 * Perform ECDH using KSM-managed key (fully implicit).
 * No key management required - just provide peer's public key.
 *
 * @param peerPub Peer's public key (X9.63 format)
 * @param peerLen Peer's public key length
 * @param secret Shared secret output buffer
 * @param secretLen [in/out] Buffer size, receives secret size
 * @param curveId Curve ID (ECC_SECP256R1, ECC_SECP384R1)
 *
 * @return 0 on success, negative on error
 */
WOLFSSL_API int wolfKSM_EccDhAgree(const byte* peerPub, word32 peerLen,
                                    byte* secret, word32* secretLen,
                                    int curveId);
#endif /* !NO_ECC */

#ifndef NO_RSA
/**
 * RSA sign using KSM-managed key (fully implicit).
 * No key management required - just specify the key size.
 *
 * @param in Data to sign
 * @param inLen Data length
 * @param out Signature output buffer
 * @param outLen [in/out] Buffer size, receives signature size
 * @param keySize RSA key size in bits (2048, 4096)
 *
 * @return Signature size on success, negative on error
 */
WOLFSSL_API int wolfKSM_RsaSign(const byte* in, word32 inLen,
                                 byte* out, word32* outLen,
                                 int keySize);

/**
 * RSA decrypt using KSM-managed key (fully implicit).
 * No key management required - just specify the key size.
 *
 * @param in Ciphertext
 * @param inLen Ciphertext length
 * @param out Plaintext output buffer
 * @param outLen [in/out] Buffer size, receives plaintext size
 * @param keySize RSA key size in bits (2048, 4096)
 *
 * @return Plaintext size on success, negative on error
 */
WOLFSSL_API int wolfKSM_RsaDecrypt(const byte* in, word32 inLen,
                                    byte* out, word32* outLen,
                                    int keySize);
#endif /* !NO_RSA */

/* ============================================================
 * Key Generation Helpers (Explicit Key Management)
 * ============================================================ */

#ifndef NO_ECC
#include <wolfssl/wolfcrypt/ecc.h>

/**
 * Generate an ECC key in KSM and populate wolfCrypt ecc_key structure.
 * The private key stays in KSM, only the public key is exported.
 *
 * @param key ecc_key structure to populate
 * @param rng Random number generator (unused, KSM has its own RNG)
 * @param keysize Key size in bytes (32 for P-256, 48 for P-384)
 * @param curveId Curve ID (ECC_SECP256R1, ECC_SECP384R1)
 * @param ksmId [out] Receives the KSM key handle
 *
 * @return 0 on success, negative on error
 */
WOLFSSL_API int wolfKSM_MakeEccKey(ecc_key* key, WC_RNG* rng,
                                    int keysize, int curveId,
                                    ksm_key_id* ksmId);
#endif /* !NO_ECC */

#ifndef NO_RSA
#include <wolfssl/wolfcrypt/rsa.h>

/**
 * Generate an RSA key in KSM and populate wolfCrypt RsaKey structure.
 * The private key stays in KSM, only the public key is exported.
 *
 * @param key RsaKey structure to populate
 * @param size Key size in bits (2048, 4096)
 * @param e Public exponent (typically 65537)
 * @param rng Random number generator (unused, KSM has its own RNG)
 * @param ksmId [out] Receives the KSM key handle
 *
 * @return 0 on success, negative on error
 */
WOLFSSL_API int wolfKSM_MakeRsaKey(RsaKey* key, int size, long e,
                                    WC_RNG* rng, ksm_key_id* ksmId);
#endif /* !NO_RSA */

/* ============================================================
 * Ed25519 Operations (Fully Implicit)
 * ============================================================ */

#ifdef HAVE_ED25519
/**
 * Ed25519 sign using KSM-managed key (fully implicit).
 * No key management required.
 *
 * @param msg Message to sign
 * @param msgLen Message length
 * @param sig Signature output buffer
 * @param sigLen [in/out] Buffer size, receives signature size
 *
 * @return 0 on success, negative on error
 */
WOLFSSL_API int wolfKSM_Ed25519Sign(const byte* msg, word32 msgLen,
                                     byte* sig, word32* sigLen);
#endif /* HAVE_ED25519 */

/* ============================================================
 * X25519 Operations (Fully Implicit)
 * ============================================================ */

#ifdef HAVE_CURVE25519
/**
 * X25519 key exchange using KSM-managed key (fully implicit).
 * No key management required - just provide peer's public key.
 *
 * @param peerPub Peer's public key (32 bytes)
 * @param peerLen Peer's public key length (must be 32)
 * @param secret Shared secret output buffer
 * @param secretLen [in/out] Buffer size, receives secret size (32 bytes)
 *
 * @return 0 on success, negative on error
 */
WOLFSSL_API int wolfKSM_X25519SharedSecret(const byte* peerPub, word32 peerLen,
                                            byte* secret, word32* secretLen);
#endif /* HAVE_CURVE25519 */

/* ============================================================
 * Ed448 Operations (Fully Implicit)
 * ============================================================ */

#ifdef HAVE_ED448
/**
 * Ed448 sign using KSM-managed key (fully implicit).
 * No key management required.
 *
 * @param msg Message to sign
 * @param msgLen Message length
 * @param sig Signature output buffer
 * @param sigLen [in/out] Buffer size, receives signature size
 *
 * @return 0 on success, negative on error
 */
WOLFSSL_API int wolfKSM_Ed448Sign(const byte* msg, word32 msgLen,
                                   byte* sig, word32* sigLen);
#endif /* HAVE_ED448 */

/* ============================================================
 * X448 Operations (Fully Implicit)
 * ============================================================ */

#ifdef HAVE_CURVE448
/**
 * X448 key exchange using KSM-managed key (fully implicit).
 * No key management required - just provide peer's public key.
 *
 * @param peerPub Peer's public key (56 bytes)
 * @param peerLen Peer's public key length (must be 56)
 * @param secret Shared secret output buffer
 * @param secretLen [in/out] Buffer size, receives secret size (64 bytes HKDF output)
 *
 * @return 0 on success, negative on error
 */
WOLFSSL_API int wolfKSM_X448SharedSecret(const byte* peerPub, word32 peerLen,
                                          byte* secret, word32* secretLen);
#endif /* HAVE_CURVE448 */

#ifdef __cplusplus
}
#endif

#endif /* WOLF_CRYPTO_CB */
#endif /* HAVE_WOLFKSM */
#endif /* WOLF_CRYPT_KSM_CRYPTOCB_H */
