/* ksm_cryptocb.c
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
    \file wolfcrypt/src/ksm_cryptocb.c
    \brief wolfKSM integration via crypto callback framework

    This file implements the bridge between wolfCrypt and wolfKSM using
    the standard cryptocb framework. All crypto operations are routed
    through KSM when a key is tagged with the wolfKSM device ID.
*/

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_WOLFKSM

#ifdef WOLF_CRYPTO_CB

#include <wolfssl/wolfcrypt/ksm_cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfksm/ksm.h>
#include <wolfksm/ksm_error.h>

#ifdef HAVE_CURVE448
#include <wolfssl/wolfcrypt/curve448.h>
#endif
#ifdef HAVE_ED448
#include <wolfssl/wolfcrypt/ed448.h>
#endif

/* Track KSM initialization state */
static int g_ksm_initialized = 0;
static int g_cryptocb_initialized = 0;

/* ============================================================
 * Error Code Mapping
 * ============================================================ */

/* Convert KSM error codes to wolfCrypt error codes */
static int ksm_to_wc_error(int ksm_err)
{
    switch (ksm_err) {
        case KSM_SUCCESS:
            return 0;
        case KSM_E_INVALID:
            return BAD_FUNC_ARG;
        case KSM_E_FULL:
            return MEMORY_E;
        case KSM_E_UNSUPPORTED:
            return NOT_COMPILED_IN;
        case KSM_E_MEMORY:
            return MEMORY_E;
        case KSM_E_RNG:
            return RNG_FAILURE_E;
        case KSM_E_CRYPTO:
            return WC_HW_E;  /* Hardware crypto error */
        case KSM_E_BUFFER:
            return BUFFER_E;
        case KSM_E_NOT_INIT:
            return BAD_STATE_E;
        case KSM_E_TYPE_MISMATCH:
            return BAD_FUNC_ARG;
        case KSM_E_WRAP:
            return ASN_PARSE_E;
        default:
            return WC_HW_E;
    }
}

/* ============================================================
 * Policy Registry and Virtual Keys
 * ============================================================ */

/* Policy for ECC curves */
typedef struct {
    int curveId;           /* ECC_SECP256R1, ECC_SECP384R1, etc. */
    int enabled;           /* 1 if KSM should handle this curve */
    ksm_key_id ksmId;      /* KSM handle for the key */
#ifndef NO_ECC
    ecc_key virtualKey;    /* Virtual key with devId = WOLFKSM_DEVID */
#endif
} EccPolicy;

/* Policy for RSA key sizes */
typedef struct {
    int keySize;           /* 2048, 4096, etc. */
    int enabled;           /* 1 if KSM should handle this size */
    ksm_key_id ksmId;      /* KSM handle for the key */
#ifndef NO_RSA
    RsaKey virtualKey;     /* Virtual key with devId = WOLFKSM_DEVID */
#endif
} RsaPolicy;

/* Policy registries (static storage) */
#define MAX_ECC_POLICIES 8  /* Support all NIST curves + secp256k1 */
#define MAX_RSA_POLICIES 4  /* Support 1024, 2048, 3072, 4096 */
static EccPolicy g_eccPolicies[MAX_ECC_POLICIES];
static RsaPolicy g_rsaPolicies[MAX_RSA_POLICIES];
static int g_numEccPolicies = 0;
static int g_numRsaPolicies = 0;

/* Helper: Find or create ECC policy entry */
static EccPolicy* _ksm_get_ecc_policy(int curveId, int create)
{
    int i;

    /* Search for existing policy */
    for (i = 0; i < g_numEccPolicies; i++) {
        if (g_eccPolicies[i].curveId == curveId) {
            return &g_eccPolicies[i];
        }
    }

    /* Create new if requested and space available */
    if (create && g_numEccPolicies < MAX_ECC_POLICIES) {
        EccPolicy* policy = &g_eccPolicies[g_numEccPolicies++];
        XMEMSET(policy, 0, sizeof(EccPolicy));
        policy->curveId = curveId;
        return policy;
    }

    return NULL;
}

/* Helper: Find or create RSA policy entry */
static RsaPolicy* _ksm_get_rsa_policy(int keySize, int create)
{
    int i;

    /* Search for existing policy */
    for (i = 0; i < g_numRsaPolicies; i++) {
        if (g_rsaPolicies[i].keySize == keySize) {
            return &g_rsaPolicies[i];
        }
    }

    /* Create new if requested and space available */
    if (create && g_numRsaPolicies < MAX_RSA_POLICIES) {
        RsaPolicy* policy = &g_rsaPolicies[g_numRsaPolicies++];
        XMEMSET(policy, 0, sizeof(RsaPolicy));
        policy->keySize = keySize;
        return policy;
    }

    return NULL;
}

/* ============================================================
 * Crypto Callback Implementation
 * ============================================================ */

int wolfKSM_CryptoDevCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int rc = CRYPTOCB_UNAVAILABLE;

    (void)ctx;  /* Not used for KSM */

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Only handle requests for our device ID */
    if (devId != WOLFKSM_DEVID) {
        return CRYPTOCB_UNAVAILABLE;
    }

#if defined(DEBUG_CRYPTOCB) && defined(DEBUG_WOLFSSL)
    wc_CryptoCb_InfoString(info);
#endif

    /* Route based on algorithm type */
    if (info->algo_type == WC_ALGO_TYPE_PK) {
        ksm_key_id ksmId;

    #ifndef NO_RSA
        /* RSA Operations */
        if (info->pk.type == WC_PK_TYPE_RSA) {
            /* Get KSM handle from key */
            ksmId = (ksm_key_id)info->pk.rsa.key->devId;
            if ((int)ksmId == INVALID_DEVID || ksmId == 0) {
                return CRYPTOCB_UNAVAILABLE;  /* Not a KSM key */
            }

            /* RSA Sign/Decrypt operation */
            rc = ksm_sign(ksmId, info->pk.rsa.in, info->pk.rsa.inLen,
                          info->pk.rsa.out, info->pk.rsa.outLen);
            if (rc != KSM_SUCCESS) {
                WOLFSSL_MSG("wolfKSM: ksm_sign failed");
                rc = ksm_to_wc_error(rc);
            }
            else {
                rc = (int)*info->pk.rsa.outLen;  /* Return signature size */
            }
        }
    #ifdef WOLFSSL_KEY_GEN
        else if (info->pk.type == WC_PK_TYPE_RSA_KEYGEN) {
            /* RSA key generation handled by wolfKSM_MakeRsaKey() */
            /* This path shouldn't be hit if keys are generated properly */
            WOLFSSL_MSG("wolfKSM: Use wolfKSM_MakeRsaKey for key generation");
            rc = CRYPTOCB_UNAVAILABLE;
        }
    #endif
    #endif /* !NO_RSA */

    #ifdef HAVE_ECC
        /* ECC Operations */
    #ifdef HAVE_ECC_DHE
        if (info->pk.type == WC_PK_TYPE_EC_KEYGEN) {
            /* ECC key generation handled by wolfKSM_MakeEccKey() */
            WOLFSSL_MSG("wolfKSM: Use wolfKSM_MakeEccKey for key generation");
            rc = CRYPTOCB_UNAVAILABLE;
        }
        else if (info->pk.type == WC_PK_TYPE_ECDH) {
            ecc_key* private_key = info->pk.ecdh.private_key;
            ecc_key* public_key = info->pk.ecdh.public_key;
            byte peer_pub[ECC_MAXSIZE * 2 + 1];
            word32 peer_len = sizeof(peer_pub);

            /* Get KSM handle from private key */
            ksmId = (ksm_key_id)private_key->devId;
            if ((int)ksmId == INVALID_DEVID || ksmId == 0) {
                return CRYPTOCB_UNAVAILABLE;  /* Not a KSM key */
            }

            /* Export peer's public key in X9.63 format */
            rc = wc_ecc_export_x963(public_key, peer_pub, &peer_len);
            if (rc == 0) {
                /* Perform ECDH using KSM */
                rc = ksm_ecdh(ksmId, peer_pub, peer_len,
                              info->pk.ecdh.out, info->pk.ecdh.outlen);
                if (rc != KSM_SUCCESS) {
                    WOLFSSL_MSG("wolfKSM: ksm_ecdh failed");
                    rc = ksm_to_wc_error(rc);
                }
            }
            else {
                WOLFSSL_MSG("wolfKSM: wc_ecc_export_x963 failed");
            }
        }
    #endif /* HAVE_ECC_DHE */

    #ifdef HAVE_ECC_SIGN
        if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
            /* Get KSM handle from key */
            ksmId = (ksm_key_id)info->pk.eccsign.key->devId;
            if ((int)ksmId == INVALID_DEVID || ksmId == 0) {
                return CRYPTOCB_UNAVAILABLE;  /* Not a KSM key */
            }

            /* Sign using KSM */
            rc = ksm_sign(ksmId, info->pk.eccsign.in, info->pk.eccsign.inlen,
                          info->pk.eccsign.out, info->pk.eccsign.outlen);
            if (rc != KSM_SUCCESS) {
                WOLFSSL_MSG("wolfKSM: ksm_sign (ECC) failed");
                rc = ksm_to_wc_error(rc);
            }
        }
    #endif /* HAVE_ECC_SIGN */

    #ifdef HAVE_ECC_VERIFY
        if (info->pk.type == WC_PK_TYPE_ECDSA_VERIFY) {
            /* Verification doesn't need private key, use software */
            rc = CRYPTOCB_UNAVAILABLE;
        }
    #endif /* HAVE_ECC_VERIFY */
    #endif /* HAVE_ECC */
    }

    return rc;
}

/* ============================================================
 * Registration Helpers
 * ============================================================ */

int wolfKSM_SetCryptoDevCb(int* pDevId)
{
    int rc;
    int devId = WOLFKSM_DEVID;

    /* Initialize crypto callback device table once */
    if (!g_cryptocb_initialized) {
        wc_CryptoCb_Init();
        g_cryptocb_initialized = 1;
    }

    /* Initialize KSM if not already done */
    if (!g_ksm_initialized) {
        rc = ksm_init();
        if (rc != KSM_SUCCESS) {
            WOLFSSL_MSG("wolfKSM: ksm_init failed");
            return ksm_to_wc_error(rc);
        }
        g_ksm_initialized = 1;
        WOLFSSL_MSG("wolfKSM: initialized successfully");
    }

    /* Register crypto callback */
    rc = wc_CryptoCb_RegisterDevice(devId, wolfKSM_CryptoDevCb, NULL);
    if (rc != 0) {
        WOLFSSL_MSG("wolfKSM: wc_CryptoCb_RegisterDevice failed");
        return rc;
    }

    if (pDevId != NULL) {
        *pDevId = devId;
    }

    WOLFSSL_MSG("wolfKSM: crypto callback registered");
    return 0;
}

int wolfKSM_ClearCryptoDevCb(int devId)
{
    if (devId != WOLFKSM_DEVID) {
        return BAD_FUNC_ARG;
    }

    /* Unregister crypto callback */
    wc_CryptoCb_UnRegisterDevice(devId);

    /* Shutdown KSM */
    if (g_ksm_initialized) {
        ksm_shutdown();
        g_ksm_initialized = 0;
        WOLFSSL_MSG("wolfKSM: shutdown complete");
    }

    return 0;
}

/* ============================================================
 * Policy-Based Key Management (Fully Implicit API)
 * ============================================================ */

int wolfKSM_SetPolicy(int curveId, int enable)
{
    int rc;
    EccPolicy* policy;

    /* Ensure KSM is initialized */
    if (!g_ksm_initialized) {
        rc = wolfKSM_SetCryptoDevCb(NULL);
        if (rc != 0) {
            return rc;
        }
    }

    /* Get or create policy entry */
    policy = _ksm_get_ecc_policy(curveId, enable);
    if (policy == NULL) {
        if (enable) {
            WOLFSSL_MSG("wolfKSM: Policy table full");
            return MEMORY_E;
        }
        /* Disabling non-existent policy is OK */
        return 0;
    }

    /* If enabling and not already set up, generate key */
    if (enable && !policy->enabled) {
#ifndef NO_ECC
        /* Generate key in KSM for this curve */
        rc = wolfKSM_MakeEccKey(&policy->virtualKey, NULL, 0, curveId,
                                &policy->ksmId);
        if (rc != 0) {
            WOLFSSL_MSG("wolfKSM: Failed to generate policy key");
            return rc;
        }
#else
        return NOT_COMPILED_IN;
#endif
        policy->enabled = 1;
        WOLFSSL_MSG("wolfKSM: Policy enabled for ECC curve");
    }
    /* If disabling, destroy key */
    else if (!enable && policy->enabled) {
        ksm_destroy(policy->ksmId);
        policy->enabled = 0;
        policy->ksmId = 0;
        WOLFSSL_MSG("wolfKSM: Policy disabled for ECC curve");
    }

    return 0;
}

#ifndef NO_ECC
ecc_key* wolfKSM_GetDefaultEccKey(int curveId)
{
    EccPolicy* policy = _ksm_get_ecc_policy(curveId, 0);
    if (policy != NULL && policy->enabled) {
        return &policy->virtualKey;
    }
    return NULL;
}
#endif

#ifndef NO_RSA
RsaKey* wolfKSM_GetDefaultRsaKey(int keySize)
{
    RsaPolicy* policy = _ksm_get_rsa_policy(keySize, 0);
    if (policy != NULL && policy->enabled) {
        return &policy->virtualKey;
    }
    return NULL;
}
#endif

/* ============================================================
 * Fully Implicit Crypto Operations (No Key Management!)
 * ============================================================ */

#ifndef NO_ECC
int wolfKSM_EccSignHash(const byte* hash, word32 hashLen,
                         byte* sig, word32* sigLen,
                         int curveId)
{
    int rc;
    EccPolicy* policy;

    if (hash == NULL || sig == NULL || sigLen == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Ensure KSM is initialized */
    if (!g_ksm_initialized) {
        rc = wolfKSM_SetCryptoDevCb(NULL);
        if (rc != 0) {
            return rc;
        }
    }

    /* Get policy (auto-create if not set) */
    policy = _ksm_get_ecc_policy(curveId, 1);
    if (policy == NULL) {
        WOLFSSL_MSG("wolfKSM: Policy table full");
        return MEMORY_E;
    }

    /* Auto-generate key if policy not enabled yet */
    if (!policy->enabled) {
        rc = wolfKSM_SetPolicy(curveId, 1);
        if (rc != 0) {
            return rc;
        }
    }

    /* Sign using KSM */
    rc = ksm_sign(policy->ksmId, hash, hashLen, sig, sigLen);
    if (rc != KSM_SUCCESS) {
        WOLFSSL_MSG("wolfKSM: ksm_sign failed in implicit wrapper");
        return ksm_to_wc_error(rc);
    }

    return 0;
}

int wolfKSM_EccDhAgree(const byte* peerPub, word32 peerLen,
                        byte* secret, word32* secretLen,
                        int curveId)
{
    int rc;
    EccPolicy* policy;

    if (peerPub == NULL || secret == NULL || secretLen == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Ensure KSM is initialized */
    if (!g_ksm_initialized) {
        rc = wolfKSM_SetCryptoDevCb(NULL);
        if (rc != 0) {
            return rc;
        }
    }

    /* Get policy (auto-create if not set) */
    policy = _ksm_get_ecc_policy(curveId, 1);
    if (policy == NULL) {
        WOLFSSL_MSG("wolfKSM: Policy table full");
        return MEMORY_E;
    }

    /* Auto-generate key if policy not enabled yet */
    if (!policy->enabled) {
        rc = wolfKSM_SetPolicy(curveId, 1);
        if (rc != 0) {
            return rc;
        }
    }

    /* Perform ECDH using KSM */
    rc = ksm_ecdh(policy->ksmId, peerPub, peerLen, secret, secretLen);
    if (rc != KSM_SUCCESS) {
        WOLFSSL_MSG("wolfKSM: ksm_ecdh failed in implicit wrapper");
        return ksm_to_wc_error(rc);
    }

    return 0;
}
#endif /* !NO_ECC */

#ifndef NO_RSA
int wolfKSM_RsaSign(const byte* in, word32 inLen,
                     byte* out, word32* outLen,
                     int keySize)
{
    int rc;
    RsaPolicy* policy;

    if (in == NULL || out == NULL || outLen == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Ensure KSM is initialized */
    if (!g_ksm_initialized) {
        rc = wolfKSM_SetCryptoDevCb(NULL);
        if (rc != 0) {
            return rc;
        }
    }

    /* Get policy (auto-create if not set) */
    policy = _ksm_get_rsa_policy(keySize, 1);
    if (policy == NULL) {
        WOLFSSL_MSG("wolfKSM: Policy table full");
        return MEMORY_E;
    }

    /* Auto-generate key if policy not enabled yet */
    if (!policy->enabled) {
        ksm_key_type type;
        ksm_key_id id;

        /* Map size to KSM key type */
        switch (keySize) {
            case 1024:
                type = KSM_TYPE_RSA_1024;
                break;
            case 2048:
                type = KSM_TYPE_RSA_2048;
                break;
            case 3072:
                type = KSM_TYPE_RSA_3072;
                break;
            case 4096:
                type = KSM_TYPE_RSA_4096;
                break;
            default:
                WOLFSSL_MSG("wolfKSM: Unsupported RSA key size");
                return NOT_COMPILED_IN;
        }

        /* Generate key in KSM */
        rc = ksm_generate(type, &id);
        if (rc != KSM_SUCCESS) {
            WOLFSSL_MSG("wolfKSM: ksm_generate failed");
            return ksm_to_wc_error(rc);
        }

        policy->ksmId = id;
        policy->enabled = 1;
        WOLFSSL_MSG("wolfKSM: Auto-generated RSA key for implicit policy");
    }

    /* Sign using KSM */
    rc = ksm_sign(policy->ksmId, in, inLen, out, outLen);
    if (rc != KSM_SUCCESS) {
        WOLFSSL_MSG("wolfKSM: ksm_sign failed in implicit wrapper");
        return ksm_to_wc_error(rc);
    }

    return (int)*outLen;  /* Return signature size like RSA functions */
}

int wolfKSM_RsaDecrypt(const byte* in, word32 inLen,
                        byte* out, word32* outLen,
                        int keySize)
{
    int rc;
    RsaPolicy* policy;

    if (in == NULL || out == NULL || outLen == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Ensure KSM is initialized */
    if (!g_ksm_initialized) {
        rc = wolfKSM_SetCryptoDevCb(NULL);
        if (rc != 0) {
            return rc;
        }
    }

    /* Get policy (auto-create if not set) */
    policy = _ksm_get_rsa_policy(keySize, 1);
    if (policy == NULL) {
        WOLFSSL_MSG("wolfKSM: Policy table full");
        return MEMORY_E;
    }

    /* Auto-generate key if policy not enabled yet */
    if (!policy->enabled) {
        ksm_key_type type;
        ksm_key_id id;

        /* Map size to KSM key type */
        switch (keySize) {
            case 1024:
                type = KSM_TYPE_RSA_1024;
                break;
            case 2048:
                type = KSM_TYPE_RSA_2048;
                break;
            case 3072:
                type = KSM_TYPE_RSA_3072;
                break;
            case 4096:
                type = KSM_TYPE_RSA_4096;
                break;
            default:
                WOLFSSL_MSG("wolfKSM: Unsupported RSA key size");
                return NOT_COMPILED_IN;
        }

        /* Generate key in KSM */
        rc = ksm_generate(type, &id);
        if (rc != KSM_SUCCESS) {
            WOLFSSL_MSG("wolfKSM: ksm_generate failed");
            return ksm_to_wc_error(rc);
        }

        policy->ksmId = id;
        policy->enabled = 1;
        WOLFSSL_MSG("wolfKSM: Auto-generated RSA key for implicit policy");
    }

    /* Decrypt using KSM (ksm_sign handles both sign and decrypt for RSA) */
    rc = ksm_sign(policy->ksmId, in, inLen, out, outLen);
    if (rc != KSM_SUCCESS) {
        WOLFSSL_MSG("wolfKSM: ksm_sign (decrypt) failed in implicit wrapper");
        return ksm_to_wc_error(rc);
    }

    return (int)*outLen;  /* Return plaintext size */
}
#endif /* !NO_RSA */

/* ============================================================
 * Key Generation Helpers (Explicit Key Management)
 * ============================================================ */

#ifndef NO_ECC
int wolfKSM_MakeEccKey(ecc_key* key, WC_RNG* rng, int keysize, int curveId,
                        ksm_key_id* ksmId)
{
    int rc;
    ksm_key_id id;
    ksm_key_type type;
    byte pubkey[ECC_MAXSIZE * 2 + 1];  /* X9.63 format: 0x04 || x || y */
    word32 pubkey_len = sizeof(pubkey);

    if (key == NULL || ksmId == NULL) {
        return BAD_FUNC_ARG;
    }

    (void)rng;      /* KSM has its own RNG */
    (void)keysize;  /* Determined by curve */

    /* Ensure KSM is initialized */
    if (!g_ksm_initialized) {
        rc = wolfKSM_SetCryptoDevCb(NULL);
        if (rc != 0) {
            return rc;
        }
    }

    /* Map curve ID to KSM key type */
    switch (curveId) {
        case ECC_SECP192R1:
            type = KSM_TYPE_ECC_P192;
            break;
        case ECC_SECP224R1:
            type = KSM_TYPE_ECC_P224;
            break;
        case ECC_SECP256R1:
            type = KSM_TYPE_ECC_P256;
            break;
        case ECC_SECP384R1:
            type = KSM_TYPE_ECC_P384;
            break;
        case ECC_SECP521R1:
            type = KSM_TYPE_ECC_P521;
            break;
        case ECC_SECP256K1:
            type = KSM_TYPE_ECC_SECP256K1;
            break;
        default:
            WOLFSSL_MSG("wolfKSM: Unsupported ECC curve");
            return NOT_COMPILED_IN;
    }

    /* Generate key inside KSM */
    rc = ksm_generate(type, &id);
    if (rc != KSM_SUCCESS) {
        WOLFSSL_MSG("wolfKSM: ksm_generate failed");
        return ksm_to_wc_error(rc);
    }

    /* Export public key from KSM */
    rc = ksm_export_pubkey(id, pubkey, &pubkey_len);
    if (rc != KSM_SUCCESS) {
        ksm_destroy(id);
        WOLFSSL_MSG("wolfKSM: ksm_export_pubkey failed");
        return ksm_to_wc_error(rc);
    }

    /* Import public key into wolfCrypt ecc_key structure */
    rc = wc_ecc_import_x963(pubkey, pubkey_len, key);
    if (rc != 0) {
        ksm_destroy(id);
        WOLFSSL_MSG("wolfKSM: wc_ecc_import_x963 failed");
        return rc;
    }

    /* Tag key as belonging to KSM device */
    key->devId = WOLFKSM_DEVID;

    /* Return KSM handle to caller */
    *ksmId = id;

    WOLFSSL_MSG("wolfKSM: ECC key generated successfully");
    return 0;
}
#endif /* !NO_ECC */

#ifndef NO_RSA
int wolfKSM_MakeRsaKey(RsaKey* key, int size, long e, WC_RNG* rng,
                        ksm_key_id* ksmId)
{
    int rc;
    ksm_key_id id;
    ksm_key_type type;
    byte pubkey[512];  /* DER format */
    word32 pubkey_len = sizeof(pubkey);
    word32 idx = 0;

    if (key == NULL || ksmId == NULL) {
        return BAD_FUNC_ARG;
    }

    (void)rng;  /* KSM has its own RNG */
    (void)e;    /* KSM uses fixed exponent (65537) */

    /* Ensure KSM is initialized */
    if (!g_ksm_initialized) {
        rc = wolfKSM_SetCryptoDevCb(NULL);
        if (rc != 0) {
            return rc;
        }
    }

    /* Map size to KSM key type */
    switch (size) {
        case 1024:
            type = KSM_TYPE_RSA_1024;
            break;
        case 2048:
            type = KSM_TYPE_RSA_2048;
            break;
        case 3072:
            type = KSM_TYPE_RSA_3072;
            break;
        case 4096:
            type = KSM_TYPE_RSA_4096;
            break;
        default:
            WOLFSSL_MSG("wolfKSM: Unsupported RSA key size");
            return NOT_COMPILED_IN;
    }

    /* Generate key inside KSM */
    rc = ksm_generate(type, &id);
    if (rc != KSM_SUCCESS) {
        WOLFSSL_MSG("wolfKSM: ksm_generate failed");
        return ksm_to_wc_error(rc);
    }

    /* Export public key from KSM */
    rc = ksm_export_pubkey(id, pubkey, &pubkey_len);
    if (rc != KSM_SUCCESS) {
        ksm_destroy(id);
        WOLFSSL_MSG("wolfKSM: ksm_export_pubkey failed");
        return ksm_to_wc_error(rc);
    }

    /* Import public key into wolfCrypt RsaKey structure */
    rc = wc_RsaPublicKeyDecode(pubkey, &idx, key, pubkey_len);
    if (rc != 0) {
        ksm_destroy(id);
        WOLFSSL_MSG("wolfKSM: wc_RsaPublicKeyDecode failed");
        return rc;
    }

    /* Set key type to RSA (required for operations) */
    key->type = RSA_PUBLIC;

    /* Set RNG for encryption operations (required for padding) */
    rc = wc_RsaSetRNG(key, rng);
    if (rc != 0) {
        ksm_destroy(id);
        WOLFSSL_MSG("wolfKSM: wc_RsaSetRNG failed");
        return rc;
    }

    /* Tag key as belonging to KSM device */
    key->devId = WOLFKSM_DEVID;

    /* Return KSM handle to caller */
    *ksmId = id;

    WOLFSSL_MSG("wolfKSM: RSA key generated successfully");
    return 0;
}
#endif /* !NO_RSA */

/* ============================================================
 * Ed25519 Implicit Operations
 * ============================================================ */

#ifdef HAVE_ED25519
/* Static policy for Ed25519 (single default key) */
static struct {
    int enabled;
    ksm_key_id ksmId;
} g_ed25519_policy = {0, KSM_KEY_INVALID};

WOLFSSL_API int wolfKSM_Ed25519Sign(const byte* msg, word32 msgLen,
                                     byte* sig, word32* sigLen)
{
    int rc;

    WOLFSSL_ENTER("wolfKSM_Ed25519Sign");

    if (msg == NULL || sig == NULL || sigLen == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Ensure KSM is initialized */
    if (!g_ksm_initialized) {
        rc = wolfKSM_SetCryptoDevCb(NULL);
        if (rc != 0) {
            return rc;
        }
    }

    /* Auto-generate key if not created yet */
    if (!g_ed25519_policy.enabled) {
        rc = ksm_generate(KSM_TYPE_ED25519, &g_ed25519_policy.ksmId);
        if (rc != KSM_SUCCESS) {
            WOLFSSL_MSG("wolfKSM: Ed25519 key generation failed");
            return ksm_to_wc_error(rc);
        }
        g_ed25519_policy.enabled = 1;
        WOLFSSL_MSG("wolfKSM: Ed25519 key auto-generated");
    }

    /* Sign with KSM */
    rc = ksm_sign(g_ed25519_policy.ksmId, msg, msgLen, sig, sigLen);
    if (rc != KSM_SUCCESS) {
        WOLFSSL_MSG("wolfKSM: ksm_sign (Ed25519) failed");
        return ksm_to_wc_error(rc);
    }

    WOLFSSL_MSG("wolfKSM: Ed25519 sign successful");
    return 0;
}
#endif /* HAVE_ED25519 */

/* ============================================================
 * X25519 Implicit Operations
 * ============================================================ */

#ifdef HAVE_CURVE25519
/* Static policy for X25519 (single default key) */
static struct {
    int enabled;
    ksm_key_id ksmId;
} g_x25519_policy = {0, KSM_KEY_INVALID};

WOLFSSL_API int wolfKSM_X25519SharedSecret(const byte* peerPub, word32 peerLen,
                                            byte* secret, word32* secretLen)
{
    int rc;

    WOLFSSL_ENTER("wolfKSM_X25519SharedSecret");

    if (peerPub == NULL || secret == NULL || secretLen == NULL) {
        return BAD_FUNC_ARG;
    }

    if (peerLen != CURVE25519_KEYSIZE) {
        WOLFSSL_MSG("wolfKSM: Invalid X25519 peer public key length");
        return BAD_FUNC_ARG;
    }

    /* Ensure KSM is initialized */
    if (!g_ksm_initialized) {
        rc = wolfKSM_SetCryptoDevCb(NULL);
        if (rc != 0) {
            return rc;
        }
    }

    /* Auto-generate key if not created yet */
    if (!g_x25519_policy.enabled) {
        rc = ksm_generate(KSM_TYPE_X25519, &g_x25519_policy.ksmId);
        if (rc != KSM_SUCCESS) {
            WOLFSSL_MSG("wolfKSM: X25519 key generation failed");
            return ksm_to_wc_error(rc);
        }
        g_x25519_policy.enabled = 1;
        WOLFSSL_MSG("wolfKSM: X25519 key auto-generated");
    }

    /* Perform ECDH with KSM */
    rc = ksm_ecdh(g_x25519_policy.ksmId, peerPub, peerLen, secret, secretLen);
    if (rc != KSM_SUCCESS) {
        WOLFSSL_MSG("wolfKSM: ksm_ecdh (X25519) failed");
        return ksm_to_wc_error(rc);
    }

    WOLFSSL_MSG("wolfKSM: X25519 ECDH successful");
    return 0;
}
#endif /* HAVE_CURVE25519 */

/* ============================================================
 * Ed448 Implicit Operations
 * ============================================================ */

#ifdef HAVE_ED448
/* Static policy for Ed448 (single default key) */
static struct {
    int enabled;
    ksm_key_id ksmId;
} g_ed448_policy = {0, KSM_KEY_INVALID};

WOLFSSL_API int wolfKSM_Ed448Sign(const byte* msg, word32 msgLen,
                                   byte* sig, word32* sigLen)
{
    int rc;

    WOLFSSL_ENTER("wolfKSM_Ed448Sign");

    if (msg == NULL || sig == NULL || sigLen == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Ensure KSM is initialized */
    if (!g_ksm_initialized) {
        rc = wolfKSM_SetCryptoDevCb(NULL);
        if (rc != 0) {
            return rc;
        }
    }

    /* Auto-generate key if not created yet */
    if (!g_ed448_policy.enabled) {
        rc = ksm_generate(KSM_TYPE_ED448, &g_ed448_policy.ksmId);
        if (rc != KSM_SUCCESS) {
            WOLFSSL_MSG("wolfKSM: Ed448 key generation failed");
            return ksm_to_wc_error(rc);
        }
        g_ed448_policy.enabled = 1;
        WOLFSSL_MSG("wolfKSM: Ed448 key auto-generated");
    }

    /* Sign with KSM */
    rc = ksm_sign(g_ed448_policy.ksmId, msg, msgLen, sig, sigLen);
    if (rc != KSM_SUCCESS) {
        WOLFSSL_MSG("wolfKSM: ksm_sign (Ed448) failed");
        return ksm_to_wc_error(rc);
    }

    WOLFSSL_MSG("wolfKSM: Ed448 sign successful");
    return 0;
}
#endif /* HAVE_ED448 */

/* ============================================================
 * X448 Implicit Operations
 * ============================================================ */

#ifdef HAVE_CURVE448
/* Static policy for X448 (single default key) */
static struct {
    int enabled;
    ksm_key_id ksmId;
} g_x448_policy = {0, KSM_KEY_INVALID};

WOLFSSL_API int wolfKSM_X448SharedSecret(const byte* peerPub, word32 peerLen,
                                          byte* secret, word32* secretLen)
{
    int rc;

    WOLFSSL_ENTER("wolfKSM_X448SharedSecret");

    if (peerPub == NULL || secret == NULL || secretLen == NULL) {
        return BAD_FUNC_ARG;
    }

    if (peerLen != CURVE448_KEY_SIZE) {
        WOLFSSL_MSG("wolfKSM: Invalid X448 peer public key length");
        return BAD_FUNC_ARG;
    }

    /* Ensure KSM is initialized */
    if (!g_ksm_initialized) {
        rc = wolfKSM_SetCryptoDevCb(NULL);
        if (rc != 0) {
            return rc;
        }
    }

    /* Auto-generate key if not created yet */
    if (!g_x448_policy.enabled) {
        rc = ksm_generate(KSM_TYPE_X448, &g_x448_policy.ksmId);
        if (rc != KSM_SUCCESS) {
            WOLFSSL_MSG("wolfKSM: X448 key generation failed");
            return ksm_to_wc_error(rc);
        }
        g_x448_policy.enabled = 1;
        WOLFSSL_MSG("wolfKSM: X448 key auto-generated");
    }

    /* Perform ECDH with KSM */
    rc = ksm_ecdh(g_x448_policy.ksmId, peerPub, peerLen, secret, secretLen);
    if (rc != KSM_SUCCESS) {
        WOLFSSL_MSG("wolfKSM: ksm_ecdh (X448) failed");
        return ksm_to_wc_error(rc);
    }

    WOLFSSL_MSG("wolfKSM: X448 ECDH successful");
    return 0;
}
#endif /* HAVE_CURVE448 */

#endif /* WOLF_CRYPTO_CB */
#endif /* HAVE_WOLFKSM */
