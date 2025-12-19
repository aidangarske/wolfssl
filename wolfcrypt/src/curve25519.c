/* curve25519.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


 /* Based On Daniel J Bernstein's curve25519 Public Domain ref10 work. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef NO_CURVED25519_X64
    #undef USE_INTEL_SPEEDUP
#endif

#ifdef HAVE_CURVE25519

#include <stdio.h>  /* For fprintf debug output */
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ge_operations.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(FREESCALE_LTC_ECC)
    #include <wolfssl/wolfcrypt/port/nxp/ksdk_port.h>
#endif
#ifdef WOLFSSL_SE050
    #include <wolfssl/wolfcrypt/port/nxp/se050_port.h>
#endif

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#if defined(WOLFSSL_CURVE25519_BLINDING)
    #if defined(CURVE25519_SMALL)
        #error "Blinding not needed nor available for small implementation"
    #elif defined(USE_INTEL_SPEEDUP) || defined(WOLFSSL_ARMASM)
        #error "Blinding not needed nor available for assembly implementation"
    #elif defined(WOLFSSL_CURVE25519_USE_ED25519)
        #error "Ed25519 base scalar mult cannot be used with blinding "
    #endif
#endif

#if defined(WOLFSSL_USE_SAVE_VECTOR_REGISTERS) && !defined(USE_INTEL_SPEEDUP)
    /* force off unneeded vector register save/restore. */
    #undef SAVE_VECTOR_REGISTERS
    #define SAVE_VECTOR_REGISTERS(fail_clause) SAVE_NO_VECTOR_REGISTERS(fail_clause)
    #undef RESTORE_VECTOR_REGISTERS
    #define RESTORE_VECTOR_REGISTERS() RESTORE_NO_VECTOR_REGISTERS()
#endif

const curve25519_set_type curve25519_sets[] = {
    {
        CURVE25519_KEYSIZE,
        "CURVE25519",
    }
};

#if !defined(WOLFSSL_CURVE25519_USE_ED25519) || \
    defined(WOLFSSL_CURVE25519_BLINDING)
static const word32 kCurve25519BasePoint[CURVE25519_KEYSIZE/sizeof(word32)] = {
#ifdef BIG_ENDIAN_ORDER
    0x09000000
#else
    9
#endif
};
#endif /* !WOLFSSL_CURVE25519_USE_ED25519 || WOLFSSL_CURVE25519_BLINDING */

/* Curve25519 private key must be less than order */
/* These functions clamp private k and check it */
static WC_INLINE int curve25519_priv_clamp(byte* priv)
{
    priv[0]  &= 248;
    priv[CURVE25519_KEYSIZE-1] &= 127;
    priv[CURVE25519_KEYSIZE-1] |= 64;
    return 0;
}
static WC_INLINE int curve25519_priv_clamp_check(const byte* priv)
{
    /* check that private part of key has been clamped */
    int ret = 0;
    if ((priv[0] & ~248) ||
        (priv[CURVE25519_KEYSIZE-1] & 128)) {
        ret = ECC_BAD_ARG_E;
    }
    return ret;
}

static WC_INLINE void curve25519_copy_point(byte* out, const byte* point,
    int endian)
{
    if (endian == EC25519_BIG_ENDIAN) {
        int i;
        /* put shared secret key in Big Endian format */
        for (i = 0; i < CURVE25519_KEYSIZE; i++) {
            out[i] = point[CURVE25519_KEYSIZE - i -1];
        }
    }
    else { /* put shared secret key in Little Endian format */
        XMEMCPY(out, point, CURVE25519_KEYSIZE);
    }
}

/* compute the public key from an existing private key, using bare vectors.
 *
 * return value is propagated from curve25519() (0 on success), or
 * ECC_BAD_ARG_E, and the byte vectors are little endian.
 */
int wc_curve25519_make_pub(int public_size, byte* pub, int private_size,
                           const byte* priv)
{
    int ret;
#ifdef FREESCALE_LTC_ECC
    const ECPoint* basepoint = nxp_ltc_curve25519_GetBasePoint();
    ECPoint wc_pub;
#endif

    if ( (public_size != CURVE25519_KEYSIZE) ||
        (private_size != CURVE25519_KEYSIZE)) {
        return ECC_BAD_ARG_E;
    }
    if ((pub == NULL) || (priv == NULL)) {
        return ECC_BAD_ARG_E;
    }

    /* check clamping */
    ret = curve25519_priv_clamp_check(priv);
    if (ret != 0)
        return ret;

#ifdef FREESCALE_LTC_ECC
    /* input basepoint on Weierstrass curve */
    ret = nxp_ltc_curve25519(&wc_pub, priv, basepoint, kLTC_Weierstrass);
    if (ret == 0) {
        XMEMCPY(pub, wc_pub.point, CURVE25519_KEYSIZE);
    }
#else
#ifndef WOLFSSL_CURVE25519_BLINDING
    fe_init();

    SAVE_VECTOR_REGISTERS(return _svr_ret;);

#if defined(WOLFSSL_CURVE25519_USE_ED25519)
    {
        ge_p3 A;

        ge_scalarmult_base(&A, priv);
    #ifndef CURVE25519_SMALL
        fe_add(A.X, A.Z, A.Y);
        fe_sub(A.T, A.Z, A.Y);
        fe_invert(A.T, A.T);
        fe_mul(A.T, A.X, A.T);
        fe_tobytes(pub, A.T);
    #else
        lm_add(A.X, A.Z, A.Y);
        lm_sub(A.T, A.Z, A.Y);
        lm_invert(A.T, A.T);
        lm_mul(pub, A.X, A.T);
    #endif
        ret = 0;
    }
#elif defined(CURVED25519_X64) || (defined(WOLFSSL_ARMASM) && \
    defined(__aarch64__))
    ret = curve25519_base(pub, priv);
#else
    ret = curve25519(pub, priv, (byte*)kCurve25519BasePoint);
#endif

    RESTORE_VECTOR_REGISTERS();
#else
    {
        WC_RNG rng;

        ret = wc_InitRng(&rng);
        if (ret == 0) {
            ret = wc_curve25519_make_pub_blind(public_size, pub, private_size,
                priv, &rng);

            wc_FreeRng(&rng);
        }
    }
#endif /* !WOLFSSL_CURVE25519_BLINDING */
#endif /* FREESCALE_LTC_ECC */

    return ret;
}

#ifdef WOLFSSL_CURVE25519_BLINDING
#ifndef FREESCALE_LTC_ECC
#ifndef WOLFSSL_CURVE25519_BLINDING_RAND_CNT
    #define WOLFSSL_CURVE25519_BLINDING_RAND_CNT    10
#endif
static int curve25519_smul_blind(byte* rp, const byte* n, const byte* p,
    WC_RNG* rng)
{
    int ret;
    byte a[CURVE25519_KEYSIZE];
    byte n_a[CURVE25519_KEYSIZE];
    byte rz[CURVE25519_KEYSIZE];
    int i;
    int cnt;

    fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: ENTRY\n");
    fprintf(stderr, "[WOLFSSL-DEBUG]   rp=%p, n=%p, p=%p, rng=%p\n", rp, n, p, rng);
    
    /* NULL pointer check */
    if (rp == NULL || n == NULL || p == NULL || rng == NULL) {
        fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: ERROR - NULL pointer detected! rp=%p, n=%p, p=%p, rng=%p\n", rp, n, p, rng);
        fflush(stderr);
        return ECC_BAD_ARG_E;
    }
    
    if (n != NULL) {
        fprintf(stderr, "[WOLFSSL-DEBUG]   n[0]=0x%02x, n[31]=0x%02x\n", n[0], n[31]);
    }
    if (p != NULL) {
        fprintf(stderr, "[WOLFSSL-DEBUG]   p[0]=0x%02x, p[31]=0x%02x (MSB=%s)\n", 
                p[0], p[31], (p[31] & 0x80) ? "SET" : "CLEAR");
    }
    fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: All parameters validated, proceeding...\n");
    fflush(stderr);

    fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: About to call SAVE_VECTOR_REGISTERS...\n");
    fflush(stderr);
    SAVE_VECTOR_REGISTERS(
        fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: SAVE_VECTOR_REGISTERS failed, returning _svr_ret=%d\n", _svr_ret);
        fflush(stderr);
        return _svr_ret;
    );
    fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: After SAVE_VECTOR_REGISTERS, continuing...\n");
    fflush(stderr);

    /* Generate random z. */
    fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: Starting random z generation loop...\n");
    fflush(stderr);
    for (cnt = 0; cnt < WOLFSSL_CURVE25519_BLINDING_RAND_CNT; cnt++) {
        fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: RNG z generation attempt %d/%d\n", cnt+1, WOLFSSL_CURVE25519_BLINDING_RAND_CNT);
        fflush(stderr);
        ret = wc_RNG_GenerateBlock(rng, rz, sizeof(rz));
        if (ret < 0) {
            fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: ERROR - wc_RNG_GenerateBlock failed in z loop, ret=%d\n", ret);
            fflush(stderr);
            RESTORE_VECTOR_REGISTERS();
            return ret;
        }
        for (i = CURVE25519_KEYSIZE - 1; i >= 0; i--) {
            if (rz[i] != 0xff)
                break;
        }
        if ((i >= 0) || (rz[0] <= 0xec)) {
            fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: Random z validation passed at attempt %d\n", cnt+1);
            fflush(stderr);
            break;
        }
        fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: Random z validation failed at attempt %d, continuing...\n", cnt+1);
        fflush(stderr);
    }
    if (cnt == WOLFSSL_CURVE25519_BLINDING_RAND_CNT) {
        fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: ERROR - RNG failed to generate valid z after %d attempts\n", WOLFSSL_CURVE25519_BLINDING_RAND_CNT);
        fflush(stderr);
        return RNG_FAILURE_E;
    }
    fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: Generated random z successfully (cnt=%d)\n", cnt);
    fflush(stderr);

    /* Generate 253 random bits. */
    ret = wc_RNG_GenerateBlock(rng, a, sizeof(a));
    if (ret != 0) {
        fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: ERROR - Failed to generate random a, ret=%d\n", ret);
        fflush(stderr);
        return ret;
    }
    fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: Generated random a successfully\n");
    fflush(stderr);
    a[CURVE25519_KEYSIZE-1] &= 0x7f;
    /* k' = k ^ 2k ^ a */
    n_a[0] = n[0] ^ (byte)(n[0] << 1) ^ a[0];
    for (i = 1; i < CURVE25519_KEYSIZE; i++) {
        byte b1, b2, b3;
        b1 = n[i] ^ a[i];
        b2 = (byte)(n[i] << 1) ^ a[i];
        b3 = (n[i-1] >> 7) ^ a[i];
        n_a[i] = b1 ^ b2 ^ b3;
    }
    /* Scalar multiple blinded scalar with blinding value. */
    fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: About to call curve25519_blind...\n");
    fprintf(stderr, "[WOLFSSL-DEBUG]   rp=%p, n_a=%p, a=%p, p=%p, rz=%p\n", rp, n_a, a, p, rz);
    fprintf(stderr, "[WOLFSSL-DEBUG]   n_a[0]=0x%02x, n_a[31]=0x%02x\n", n_a[0], n_a[31]);
    fprintf(stderr, "[WOLFSSL-DEBUG]   a[0]=0x%02x, a[31]=0x%02x (MSB=%s)\n", 
            a[0], a[31], (a[31] & 0x80) ? "SET" : "CLEAR");
    fprintf(stderr, "[WOLFSSL-DEBUG]   p[31]=0x%02x (MSB=%s)\n", 
            p[31], (p[31] & 0x80) ? "SET" : "CLEAR");
    fflush(stderr);
    ret = curve25519_blind(rp, n_a, a, p, rz);
    fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: curve25519_blind returned %d\n", ret);
    fflush(stderr);

    RESTORE_VECTOR_REGISTERS();

    fprintf(stderr, "[WOLFSSL-DEBUG] curve25519_smul_blind: EXIT returning %d\n", ret);
    fflush(stderr);
    return ret;
}
#endif

int wc_curve25519_make_pub_blind(int public_size, byte* pub, int private_size,
                                 const byte* priv, WC_RNG* rng)
{
    int ret;
#ifdef FREESCALE_LTC_ECC
    const ECPoint* basepoint = nxp_ltc_curve25519_GetBasePoint();
    ECPoint wc_pub;
#endif

    if ( (public_size != CURVE25519_KEYSIZE) ||
        (private_size != CURVE25519_KEYSIZE)) {
        return ECC_BAD_ARG_E;
    }
    if ((pub == NULL) || (priv == NULL)) {
        return ECC_BAD_ARG_E;
    }

    /* check clamping */
    ret = curve25519_priv_clamp_check(priv);
    if (ret != 0)
        return ret;

#ifdef FREESCALE_LTC_ECC
    /* input basepoint on Weierstrass curve */
    ret = nxp_ltc_curve25519(&wc_pub, priv, basepoint, kLTC_Weierstrass);
    if (ret == 0) {
        XMEMCPY(pub, wc_pub.point, CURVE25519_KEYSIZE);
    }
#else
    fe_init();

    ret = curve25519_smul_blind(pub, priv, (byte*)kCurve25519BasePoint, rng);
#endif

    return ret;
}
#endif

/* compute the public key from an existing private key, with supplied basepoint,
 * using bare vectors.
 *
 * return value is propagated from curve25519() (0 on success),
 * and the byte vectors are little endian.
 */
int wc_curve25519_generic(int public_size, byte* pub,
                          int private_size, const byte* priv,
                          int basepoint_size, const byte* basepoint)
{
#ifdef FREESCALE_LTC_ECC
    /* unsupported with NXP LTC, only supports single basepoint with
     * nxp_ltc_curve25519_GetBasePoint() */
    return WC_HW_E;
#else
#ifndef WOLFSSL_CURVE25519_BLINDING
    int ret;

    if ((public_size != CURVE25519_KEYSIZE) ||
        (private_size != CURVE25519_KEYSIZE) ||
        (basepoint_size != CURVE25519_KEYSIZE)) {
        return ECC_BAD_ARG_E;
    }
    if ((pub == NULL) || (priv == NULL) || (basepoint == NULL))
        return ECC_BAD_ARG_E;

    /* check clamping */
    ret = curve25519_priv_clamp_check(priv);
    if (ret != 0)
        return ret;

    fe_init();

    SAVE_VECTOR_REGISTERS(return _svr_ret;);

    ret = curve25519(pub, priv, basepoint);

    RESTORE_VECTOR_REGISTERS();

    return ret;
#else
    WC_RNG rng;
    int ret;

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        ret = wc_curve25519_generic_blind(public_size, pub, private_size, priv,
            basepoint_size, basepoint, &rng);

        wc_FreeRng(&rng);
    }

    return ret;
#endif
#endif /* FREESCALE_LTC_ECC */
}

#ifdef WOLFSSL_CURVE25519_BLINDING
/* compute the public key from an existing private key, with supplied basepoint,
 * using bare vectors.
 *
 * return value is propagated from curve25519() (0 on success),
 * and the byte vectors are little endian.
 */
int wc_curve25519_generic_blind(int public_size, byte* pub,
                                int private_size, const byte* priv,
                                int basepoint_size, const byte* basepoint,
                                WC_RNG* rng)
{
#ifdef FREESCALE_LTC_ECC
    /* unsupported with NXP LTC, only supports single basepoint with
     * nxp_ltc_curve25519_GetBasePoint() */
    return WC_HW_E;
#else
    int ret;

    if ((public_size != CURVE25519_KEYSIZE) ||
        (private_size != CURVE25519_KEYSIZE) ||
        (basepoint_size != CURVE25519_KEYSIZE)) {
        return ECC_BAD_ARG_E;
    }
    if ((pub == NULL) || (priv == NULL) || (basepoint == NULL))
        return ECC_BAD_ARG_E;

    /* check clamping */
    ret = curve25519_priv_clamp_check(priv);
    if (ret != 0)
        return ret;

    fe_init();

    ret = curve25519_smul_blind(pub, priv, basepoint, rng);

    return ret;
#endif /* FREESCALE_LTC_ECC */
}
#endif

/* generate a new private key, as a bare vector.
 *
 * return value is propagated from wc_RNG_GenerateBlock(() (0 on success),
 * or BAD_FUNC_ARG/ECC_BAD_ARG_E, and the byte vector is little endian.
 */
int wc_curve25519_make_priv(WC_RNG* rng, int keysize, byte* key)
{
    int ret;

    if (key == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    /* currently only a key size of 32 bytes is used */
    if (keysize != CURVE25519_KEYSIZE)
        return ECC_BAD_ARG_E;

    /* random number for private key */
    ret = wc_RNG_GenerateBlock(rng, key, (word32)keysize);
    if (ret == 0) {
        /* Clamp the private key */
        ret = curve25519_priv_clamp(key);
    }

    return ret;
}

/* generate a new keypair.
 *
 * return value is propagated from wc_curve25519_make_private() or
 * wc_curve25519_make_pub() (0 on success).
 */
int wc_curve25519_make_key(WC_RNG* rng, int keysize, curve25519_key* key)
{
    int ret;

    if (key == NULL || rng == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLF_CRYPTO_CB
    if (key->devId != INVALID_DEVID) {
        ret = wc_CryptoCb_Curve25519Gen(rng, keysize, key);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif

#ifdef WOLFSSL_SE050
    ret = se050_curve25519_create_key(key, keysize);
#else
    ret = wc_curve25519_make_priv(rng, keysize, key->k);
    if (ret == 0) {
        key->privSet = 1;
#ifdef WOLFSSL_CURVE25519_BLINDING
        ret = wc_curve25519_make_pub_blind((int)sizeof(key->p.point),
                                           key->p.point, (int)sizeof(key->k),
                                           key->k, rng);
        if (ret == 0) {
            ret = wc_curve25519_set_rng(key, rng);
        }
#else
        ret = wc_curve25519_make_pub((int)sizeof(key->p.point), key->p.point,
                                     (int)sizeof(key->k), key->k);
#endif
        if (ret == 0) {
            ret = wc_curve25519_check_public(key->p.point,
                                       (word32)sizeof(key->p.point),
                                      EC25519_LITTLE_ENDIAN);
        }
        key->pubSet = (ret == 0);
    }
#endif
    return ret;
}

#ifdef HAVE_CURVE25519_SHARED_SECRET

int wc_curve25519_shared_secret(curve25519_key* private_key,
                                curve25519_key* public_key,
                                byte* out, word32* outlen)
{
    return wc_curve25519_shared_secret_ex(private_key, public_key,
                                          out, outlen, EC25519_BIG_ENDIAN);
}

int wc_curve25519_shared_secret_ex(curve25519_key* private_key,
                                   curve25519_key* public_key,
                                   byte* out, word32* outlen, int endian)
{
    int ret;
    ECPoint o;

    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: ENTRY\n");
    fprintf(stderr, "[WOLFSSL-DEBUG]   private_key=%p, public_key=%p, out=%p, outlen=%p\n",
            private_key, public_key, out, outlen);
    if (outlen != NULL) {
        fprintf(stderr, "[WOLFSSL-DEBUG]   *outlen=%u (required: >=%d)\n", *outlen, CURVE25519_KEYSIZE);
    }
    fflush(stderr);

    /* sanity check */
    if (private_key == NULL || public_key == NULL ||
        out == NULL || outlen == NULL || *outlen < CURVE25519_KEYSIZE) {
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: FAILURE - sanity check failed (BAD_FUNC_ARG)\n");
        fflush(stderr);
        return BAD_FUNC_ARG;
    }

    /* make sure we have a populated private and public key */
    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Checking pubSet/privSet flags...\n");
    fprintf(stderr, "[WOLFSSL-DEBUG]   public_key->pubSet = %d\n", public_key->pubSet);
    #ifndef WOLFSSL_SE050
        fprintf(stderr, "[WOLFSSL-DEBUG]   private_key->privSet = %d\n", private_key->privSet);
        fprintf(stderr, "[WOLFSSL-DEBUG]   WOLFSSL_SE050 is NOT defined - checking privSet\n");
    #else
        fprintf(stderr, "[WOLFSSL-DEBUG]   WOLFSSL_SE050 is DEFINED - skipping privSet check\n");
    #endif
    fflush(stderr);

    if (!public_key->pubSet
    #ifndef WOLFSSL_SE050
        || !private_key->privSet
    #endif
    ) {
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: FAILURE - pubSet/privSet check failed!\n");
        fprintf(stderr, "[WOLFSSL-DEBUG]   public_key->pubSet = %d, private_key->privSet = %d\n", 
                public_key->pubSet, 
                #ifndef WOLFSSL_SE050
                    private_key->privSet
                #else
                    0  /* Not checked when SE050 defined */
                #endif
                );
        fflush(stderr);
        return ECC_BAD_ARG_E;
    }
    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: pubSet/privSet check passed\n");
    fflush(stderr);

    /* avoid implementation fingerprinting - make sure signed bit is not set */
    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Checking MSB on public key...\n");
    {
        byte last_byte = public_key->p.point[CURVE25519_KEYSIZE-1];
        byte msb_bit = last_byte & 0x80;
        fprintf(stderr, "[WOLFSSL-DEBUG]   public_key->p.point[%d] = 0x%02x\n", CURVE25519_KEYSIZE-1, last_byte);
        fprintf(stderr, "[WOLFSSL-DEBUG]   MSB (bit 7) = %s (0x%02x)\n", 
                msb_bit ? "SET (BAD!)" : "CLEAR (OK)", msb_bit);
        fflush(stderr);
    }

    if (public_key->p.point[CURVE25519_KEYSIZE-1] & 0x80) {
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: FAILURE - MSB check failed!\n");
        fprintf(stderr, "[WOLFSSL-DEBUG]   public_key->p.point[%d] = 0x%02x (MSB is SET)\n", 
                CURVE25519_KEYSIZE-1, public_key->p.point[CURVE25519_KEYSIZE-1]);
        fflush(stderr);
        return ECC_BAD_ARG_E;
    }
    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: MSB check passed\n");
    fflush(stderr);

    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: All validation checks passed, entering computation path...\n");
    fprintf(stderr, "[WOLFSSL-DEBUG]   private_key->devId = %d (INVALID_DEVID=%d)\n", private_key->devId, INVALID_DEVID);
    fflush(stderr);

#ifdef WOLF_CRYPTO_CB
    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Checking crypto callback...\n");
    if (private_key->devId != INVALID_DEVID) {
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Calling wc_CryptoCb_Curve25519 (devId=%d)\n", private_key->devId);
        fflush(stderr);
        ret = wc_CryptoCb_Curve25519(private_key, public_key, out, outlen,
            endian);
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: wc_CryptoCb_Curve25519 returned %d\n", ret);
        fflush(stderr);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Crypto callback returned non-UNAVAILABLE, returning %d\n", ret);
            fflush(stderr);
            return ret;
        }
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Crypto callback unavailable, falling through...\n");
        fflush(stderr);
        /* fall-through when unavailable */
    } else {
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Crypto callback not used (devId=INVALID_DEVID)\n");
        fflush(stderr);
    }
#else
    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: WOLF_CRYPTO_CB is NOT defined - skipping crypto callback check\n");
    fflush(stderr);
#endif

    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Initializing computation...\n");
    fprintf(stderr, "[WOLFSSL-DEBUG]   About to call curve25519 computation function\n");
    fprintf(stderr, "[WOLFSSL-DEBUG]   Key values (for debugging):\n");
    fprintf(stderr, "[WOLFSSL-DEBUG]     private_key->k[0]=0x%02x, private_key->k[31]=0x%02x\n", 
            private_key->k[0], private_key->k[CURVE25519_KEYSIZE-1]);
    fprintf(stderr, "[WOLFSSL-DEBUG]     public_key->p.point[0]=0x%02x, public_key->p.point[31]=0x%02x\n",
            public_key->p.point[0], public_key->p.point[CURVE25519_KEYSIZE-1]);
#ifdef FREESCALE_LTC_ECC
    fprintf(stderr, "[WOLFSSL-DEBUG]   FREESCALE_LTC_ECC is DEFINED - will use nxp_ltc_curve25519\n");
#else
    #ifdef WOLFSSL_SE050
        fprintf(stderr, "[WOLFSSL-DEBUG]   WOLFSSL_SE050 is DEFINED\n");
    #else
        #ifdef WOLFSSL_CURVE25519_BLINDING
            fprintf(stderr, "[WOLFSSL-DEBUG]   WOLFSSL_CURVE25519_BLINDING is DEFINED - will use curve25519_smul_blind\n");
        #else
            fprintf(stderr, "[WOLFSSL-DEBUG]   Will use standard curve25519\n");
        #endif
    #endif
#endif
    fflush(stderr);

    XMEMSET(&o, 0, sizeof(o));

#ifdef FREESCALE_LTC_ECC
    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Calling nxp_ltc_curve25519...\n");
    fflush(stderr);
    /* input point P on Curve25519 */
    ret = nxp_ltc_curve25519(&o, private_key->k, &public_key->p,
        kLTC_Curve25519);
    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: nxp_ltc_curve25519 returned %d\n", ret);
    fflush(stderr);
#else
    #ifdef WOLFSSL_SE050
    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Checking SE050 path...\n");
    fprintf(stderr, "[WOLFSSL-DEBUG]   private_key->privSet = %d\n", private_key->privSet);
    fflush(stderr);
    if (!private_key->privSet) {
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Using SE050 path (privSet=0)\n");
        fflush(stderr);
        /* use NXP SE050: "privSet" is not set */
        ret = se050_curve25519_shared_secret(private_key, public_key, &o);
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: se050_curve25519_shared_secret returned %d\n", ret);
        fflush(stderr);
    }
    else
    #endif
    {
#ifndef WOLFSSL_CURVE25519_BLINDING
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Calling curve25519 (standard, no blinding)...\n");
        fprintf(stderr, "[WOLFSSL-DEBUG]   private_key->k pointer = %p\n", private_key->k);
        fprintf(stderr, "[WOLFSSL-DEBUG]   public_key->p.point pointer = %p\n", public_key->p.point);
        fprintf(stderr, "[WOLFSSL-DEBUG]   o.point pointer = %p\n", o.point);
        fflush(stderr);
    SAVE_VECTOR_REGISTERS(return _svr_ret;);

    ret = curve25519(o.point, private_key->k, public_key->p.point);

    RESTORE_VECTOR_REGISTERS();
    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: curve25519 returned %d\n", ret);
    fflush(stderr);
#else
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Calling curve25519_smul_blind...\n");
        fprintf(stderr, "[WOLFSSL-DEBUG]   private_key->k pointer = %p\n", private_key->k);
        fprintf(stderr, "[WOLFSSL-DEBUG]   public_key->p.point pointer = %p\n", public_key->p.point);
        fprintf(stderr, "[WOLFSSL-DEBUG]   o.point pointer = %p\n", o.point);
        fprintf(stderr, "[WOLFSSL-DEBUG]   private_key->rng = %p\n", private_key->rng);
        if (private_key->rng == NULL) {
            fprintf(stderr, "[WOLFSSL-DEBUG]   WARNING: private_key->rng is NULL! This may cause failure!\n");
        }
        fflush(stderr);
    ret = curve25519_smul_blind(o.point, private_key->k, public_key->p.point,
                                private_key->rng);
    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: curve25519_smul_blind returned %d\n", ret);
    fflush(stderr);
#endif
    }
#endif
    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Computation completed, ret=%d\n", ret);
#ifdef WOLFSSL_ECDHX_SHARED_NOT_ZERO
    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: WOLFSSL_ECDHX_SHARED_NOT_ZERO check enabled\n");
    fflush(stderr);
    if (ret == 0) {
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Checking if shared secret is zero...\n");
        fflush(stderr);
        int i;
        byte t = 0;
        for (i = 0; i < CURVE25519_KEYSIZE; i++) {
            t |= o.point[i];
        }
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Zero check: t=0x%02x\n", t);
        fflush(stderr);
        if (t == 0) {
            fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: ERROR - Shared secret is all zeros! Setting ret=ECC_OUT_OF_RANGE_E (%d)\n", ECC_OUT_OF_RANGE_E);
            fflush(stderr);
            ret = ECC_OUT_OF_RANGE_E;
        } else {
            fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: Zero check passed (shared secret is not all zeros)\n");
            fflush(stderr);
        }
    }
#else
    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: WOLFSSL_ECDHX_SHARED_NOT_ZERO check is NOT enabled\n");
    fflush(stderr);
#endif
    if (ret == 0) {
        curve25519_copy_point(out, o.point, endian);
        *outlen = CURVE25519_KEYSIZE;
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: SUCCESS - returning 0\n");
        fflush(stderr);
    } else {
        fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: FAILURE - computation failed, ret=%d\n", ret);
        fflush(stderr);
    }

    ForceZero(&o, sizeof(o));

    fprintf(stderr, "[WOLFSSL-DEBUG] wc_curve25519_shared_secret_ex: EXIT returning %d\n", ret);
    fflush(stderr);
    return ret;
}

#endif /* HAVE_CURVE25519_SHARED_SECRET */

#ifdef HAVE_CURVE25519_KEY_EXPORT

/* export curve25519 public key (Big endian)
 * return 0 on success */
int wc_curve25519_export_public(curve25519_key* key, byte* out, word32* outLen)
{
    return wc_curve25519_export_public_ex(key, out, outLen, EC25519_BIG_ENDIAN);
}

/* export curve25519 public key (Big or Little endian)
 * return 0 on success */
int wc_curve25519_export_public_ex(curve25519_key* key, byte* out,
                                   word32* outLen, int endian)
{
    int ret = 0;

    if (key == NULL || out == NULL || outLen == NULL) {
        return BAD_FUNC_ARG;
    }

    /* check and set outgoing key size */
    if (*outLen < CURVE25519_KEYSIZE) {
        *outLen = CURVE25519_KEYSIZE;
        return ECC_BAD_ARG_E;
    }

    /* calculate public if missing */
    if (!key->pubSet) {
#ifdef WOLFSSL_CURVE25519_BLINDING
        ret = wc_curve25519_make_pub_blind((int)sizeof(key->p.point),
                                           key->p.point, (int)sizeof(key->k),
                                           key->k, key->rng);
#else
        ret = wc_curve25519_make_pub((int)sizeof(key->p.point), key->p.point,
                                     (int)sizeof(key->k), key->k);
#endif
        key->pubSet = (ret == 0);
    }
    /* export public point with endianness */
    curve25519_copy_point(out, key->p.point, endian);
    *outLen = CURVE25519_KEYSIZE;

    return ret;
}

#endif /* HAVE_CURVE25519_KEY_EXPORT */

#ifdef HAVE_CURVE25519_KEY_IMPORT

/* import curve25519 public key (Big endian)
 *  return 0 on success */
int wc_curve25519_import_public(const byte* in, word32 inLen,
                                curve25519_key* key)
{
    return wc_curve25519_import_public_ex(in, inLen, key, EC25519_BIG_ENDIAN);
}

/* import curve25519 public key (Big or Little endian)
 * return 0 on success */
int wc_curve25519_import_public_ex(const byte* in, word32 inLen,
                                curve25519_key* key, int endian)
{
#ifdef FREESCALE_LTC_ECC
    ltc_pkha_ecc_point_t ltcPoint;
#endif

    /* sanity check */
    if (key == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    /* check size of incoming keys */
    if (inLen != CURVE25519_KEYSIZE) {
       return ECC_BAD_ARG_E;
    }

    /* import public point with endianness */
    curve25519_copy_point(key->p.point, in, endian);
    key->pubSet = 1;

    key->dp = &curve25519_sets[0];

    /* LTC needs also Y coordinate - let's compute it */
#ifdef FREESCALE_LTC_ECC
    ltcPoint.X = &key->p.point[0];
    ltcPoint.Y = &key->p.pointY[0];
    LTC_PKHA_Curve25519ComputeY(&ltcPoint);
#endif

    return 0;
}

/* Check the public key value (big or little endian)
 *
 * pub     Public key bytes.
 * pubSz   Size of public key in bytes.
 * endian  Public key bytes passed in as big-endian or little-endian.
 * returns BAD_FUNC_ARGS when pub is NULL,
 *         BUFFER_E when size of public key is zero;
 *         ECC_OUT_OF_RANGE_E if the high bit is set;
 *         ECC_BAD_ARG_E if key length is not 32 bytes, public key value is
 *         zero or one; and
 *         0 otherwise.
 */
int wc_curve25519_check_public(const byte* pub, word32 pubSz, int endian)
{
    word32 i;

    if (pub == NULL)
        return BAD_FUNC_ARG;

    /* Check for empty key data */
    if (pubSz == 0)
        return BUFFER_E;

    /* Check key length */
    if (pubSz != CURVE25519_KEYSIZE)
        return ECC_BAD_ARG_E;


    if (endian == EC25519_LITTLE_ENDIAN) {
        /* Check for value of zero or one */
        for (i = CURVE25519_KEYSIZE - 1; i > 0; i--) {
            if (pub[i] != 0)
                break;
        }
        if (i == 0 && (pub[0] == 0 || pub[0] == 1))
            return ECC_BAD_ARG_E;

        /* Check high bit set */
        if (pub[CURVE25519_KEYSIZE - 1] & 0x80)
            return ECC_OUT_OF_RANGE_E;

        /* Check for order-1 or higher. */
        if (pub[CURVE25519_KEYSIZE - 1] == 0x7f) {
            for (i = CURVE25519_KEYSIZE - 2; i > 0; i--) {
                if (pub[i] != 0xff)
                    break;
            }
            if (i == 0 && (pub[0] >= 0xec))
                return ECC_BAD_ARG_E;
         }
    }
    else {
        /* Check for value of zero or one */
        for (i = 0; i < CURVE25519_KEYSIZE - 1; i++) {
            if (pub[i] != 0)
                break;
        }
        if (i == CURVE25519_KEYSIZE - 1 && (pub[i] == 0 || pub[i] == 1))
            return ECC_BAD_ARG_E;

        /* Check high bit set */
        if (pub[0] & 0x80)
            return ECC_OUT_OF_RANGE_E;

        /* Check for order-1 or higher. */
        if (pub[0] == 0x7f) {
            for (i = 1; i < CURVE25519_KEYSIZE - 1; i++) {
                if (pub[i] != 0)
                    break;
            }
            if (i == CURVE25519_KEYSIZE - 1 && (pub[i] >= 0xec))
                return ECC_BAD_ARG_E;
         }
    }

    return 0;
}

#endif /* HAVE_CURVE25519_KEY_IMPORT */


#ifdef HAVE_CURVE25519_KEY_EXPORT

/* export curve25519 private key only raw (Big endian)
 * outLen is in/out size
 * return 0 on success */
int wc_curve25519_export_private_raw(curve25519_key* key, byte* out,
                                     word32* outLen)
{
    return wc_curve25519_export_private_raw_ex(key, out, outLen,
                                               EC25519_BIG_ENDIAN);
}

/* export curve25519 private key only raw (Big or Little endian)
 * outLen is in/out size
 * return 0 on success */
int wc_curve25519_export_private_raw_ex(curve25519_key* key, byte* out,
                                        word32* outLen, int endian)
{
    /* sanity check */
    if (key == NULL || out == NULL || outLen == NULL)
        return BAD_FUNC_ARG;

    /* check size of outgoing buffer */
    if (*outLen < CURVE25519_KEYSIZE) {
        *outLen = CURVE25519_KEYSIZE;
        return ECC_BAD_ARG_E;
    }

    /* export private scalar with endianness */
    curve25519_copy_point(out, key->k, endian);
    *outLen = CURVE25519_KEYSIZE;

    return 0;
}

/* curve25519 key pair export (Big or Little endian)
 * return 0 on success */
int wc_curve25519_export_key_raw(curve25519_key* key,
                                 byte* priv, word32 *privSz,
                                 byte* pub, word32 *pubSz)
{
    return wc_curve25519_export_key_raw_ex(key, priv, privSz,
                                           pub, pubSz, EC25519_BIG_ENDIAN);
}

/* curve25519 key pair export (Big or Little endian)
 * return 0 on success */
int wc_curve25519_export_key_raw_ex(curve25519_key* key,
                                    byte* priv, word32 *privSz,
                                    byte* pub, word32 *pubSz,
                                    int endian)
{
    int ret;

    /* export private part */
    ret = wc_curve25519_export_private_raw_ex(key, priv, privSz, endian);
    if (ret != 0)
        return ret;

    /* export public part */
    return wc_curve25519_export_public_ex(key, pub, pubSz, endian);
}

#endif /* HAVE_CURVE25519_KEY_EXPORT */

#ifdef HAVE_CURVE25519_KEY_IMPORT

/* curve25519 private key import (Big endian)
 * Public key to match private key needs to be imported too
 * return 0 on success */
int wc_curve25519_import_private_raw(const byte* priv, word32 privSz,
                                     const byte* pub, word32 pubSz,
                                     curve25519_key* key)
{
    return wc_curve25519_import_private_raw_ex(priv, privSz, pub, pubSz,
                                               key, EC25519_BIG_ENDIAN);
}

/* curve25519 private key import (Big or Little endian)
 * Public key to match private key needs to be imported too
 * return 0 on success */
int wc_curve25519_import_private_raw_ex(const byte* priv, word32 privSz,
                                        const byte* pub, word32 pubSz,
                                        curve25519_key* key, int endian)
{
    int ret;

    /* import private part */
    ret = wc_curve25519_import_private_ex(priv, privSz, key, endian);
    if (ret != 0)
        return ret;

    /* import public part */
    return wc_curve25519_import_public_ex(pub, pubSz, key, endian);
}

/* curve25519 private key import only. (Big endian)
 * return 0 on success */
int wc_curve25519_import_private(const byte* priv, word32 privSz,
                                 curve25519_key* key)
{
    return wc_curve25519_import_private_ex(priv, privSz,
                                           key, EC25519_BIG_ENDIAN);
}

/* curve25519 private key import only. (Big or Little endian)
 * return 0 on success */
int wc_curve25519_import_private_ex(const byte* priv, word32 privSz,
                                    curve25519_key* key, int endian)
{
    /* sanity check */
    if (key == NULL || priv == NULL) {
        return BAD_FUNC_ARG;
    }

    /* check size of incoming keys */
    if ((int)privSz != CURVE25519_KEYSIZE) {
        return ECC_BAD_ARG_E;
    }

#ifdef WOLFSSL_SE050
#ifdef WOLFSSL_SE050_AUTO_ERASE
    wc_se050_erase_object(key->keyId);
#endif
    /* release NXP resources if set */
    se050_curve25519_free_key(key);
#endif

    /* import private scalar with endianness */
    curve25519_copy_point(key->k, priv, endian);
    key->privSet = 1;

    key->dp = &curve25519_sets[0];

    /* Clamp the key */
    return curve25519_priv_clamp(key->k);
}

#endif /* HAVE_CURVE25519_KEY_IMPORT */

#ifndef WC_NO_CONSTRUCTORS
curve25519_key* wc_curve25519_new(void* heap, int devId, int *result_code)
{
    int ret;
    curve25519_key* key = (curve25519_key*)XMALLOC(sizeof(curve25519_key), heap,
                           DYNAMIC_TYPE_CURVE25519);
    if (key == NULL) {
        ret = MEMORY_E;
    }
    else {
        ret = wc_curve25519_init_ex(key, heap, devId);
        if (ret != 0) {
            XFREE(key, heap, DYNAMIC_TYPE_CURVE25519);
            key = NULL;
        }
    }

    if (result_code != NULL)
        *result_code = ret;

    return key;
}

int wc_curve25519_delete(curve25519_key* key, curve25519_key** key_p) {
    if (key == NULL)
        return BAD_FUNC_ARG;
    wc_curve25519_free(key);
    XFREE(key, key->heap, DYNAMIC_TYPE_CURVE25519);
    if (key_p != NULL)
        *key_p = NULL;
    return 0;
}
#endif /* !WC_NO_CONSTRUCTORS */

int wc_curve25519_init_ex(curve25519_key* key, void* heap, int devId)
{
    if (key == NULL)
       return BAD_FUNC_ARG;

    XMEMSET(key, 0, sizeof(*key));

    /* currently the format for curve25519 */
    key->dp = &curve25519_sets[0];

#ifdef WOLF_CRYPTO_CB
    key->devId = devId;
#else
    (void)devId;
#endif
    (void)heap; /* if needed for XMALLOC/XFREE in future */

#ifndef FREESCALE_LTC_ECC
    fe_init();
#endif

#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Add("wc_curve25519_init_ex key->k", key->k, CURVE25519_KEYSIZE);
#endif

    return 0;
}

int wc_curve25519_init(curve25519_key* key)
{
    return wc_curve25519_init_ex(key, NULL, INVALID_DEVID);
}

/* Clean the memory of a key */
void wc_curve25519_free(curve25519_key* key)
{
    if (key == NULL)
       return;

#ifdef WOLFSSL_SE050
    se050_curve25519_free_key(key);
#endif

    ForceZero(key, sizeof(*key));

#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(key, sizeof(curve25519_key));
#endif
}

#ifdef WOLFSSL_CURVE25519_BLINDING
int wc_curve25519_set_rng(curve25519_key* key, WC_RNG* rng)
{
    if (key == NULL)
        return BAD_FUNC_ARG;
    key->rng = rng;
    return 0;
}
#endif

/* get key size */
int wc_curve25519_size(curve25519_key* key)
{
    if (key == NULL)
        return 0;

    return key->dp->size;
}

#endif /*HAVE_CURVE25519*/
