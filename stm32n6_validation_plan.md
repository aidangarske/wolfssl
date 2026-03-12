# STM32N6 wolfCrypt Hardware Crypto Validation Plan

## Context

The STM32N6 (STM32N657xx, Cortex-M55 @ 600MHz) port was recently added to wolfSSL,
including hardware HMAC support. This plan validates HMAC correctness, exercises all
crypto hardware peripherals, and produces a gap analysis with actionable recommendations.

The N6 has: HASH peripheral (SHA-1/2/3), SAES/CRYP (AES), PKA (ECC), and hardware RNG.
Existing benchmarks (IDE/STM32Cube/STM32_Benchmarks.md:1369-1445) confirm hardware
acceleration is working at expected throughput levels.

---

## RECON SUMMARY

### HMAC Call Chain (Hardware 3-Phase HMAC)
```
wc_HmacSetKey() [hmac.c:541]
  -> wc_Stm32_Hmac_GetAlgoInfo() [stm32.c:447] -- checks if algo supported in HW
  -> Pre-hash key if > blockSize via wc_Stm32_Hash_Update/Final [hmac.c:560-575]
  -> wc_Stm32_Hmac_SetKey() [stm32.c:530] -- Phase 1: feed key into HASH->DIN
  -> Sets hmac->innerHashKeyed = WC_HMAC_INNER_HASH_KEYED_DEV

wc_HmacUpdate() [hmac.c:914]
  -> wc_Stm32_Hmac_Update() [macro -> wc_Stm32_Hash_Update, stm32.h:144]
  -> Feeds message data into HASH->DIN in HMAC mode

wc_HmacFinal() [hmac.c:1043]
  -> wc_Stm32_Hmac_Final() [stm32.c:581]
  -> Phase 2: DCAL to finish message
  -> Phase 3: Re-feed key for opad, read digest
  -> Re-keys via wc_Stm32_Hmac_SetKey() for PRF/HKDF loop reuse
```

### Hardware-Accelerated Algorithms on N6
| Algorithm | Gate Macro | Status | Benchmark |
|-----------|-----------|--------|-----------|
| SHA-1 | STM32_HASH | HW active | 48 MiB/s |
| SHA-224 | STM32_HASH_SHA2 | HW active | 47 MiB/s |
| SHA-256 | STM32_HASH_SHA2 | HW active | 47 MiB/s |
| SHA-384 | STM32_HASH_SHA384 | HW active | 49 MiB/s |
| SHA-512 | STM32_HASH_SHA512 | HW active | 49 MiB/s |
| SHA-512/224 | STM32_HASH_SHA512_224 | HW active | 49 MiB/s |
| SHA-512/256 | STM32_HASH_SHA512_256 | HW active | 49 MiB/s |
| HMAC-SHA1/224/256 | STM32_HMAC | HW active | 45-46 MiB/s |
| HMAC-SHA384/512 | STM32_HMAC | HW active | 46 MiB/s |
| AES-CBC 128/192/256 | STM32_CRYPTO | HW active | ~17 MiB/s |
| AES-GCM 128/192/256 | STM32_CRYPTO_AES_GCM | HW active | ~16.5 MiB/s |
| ECC P-256 | WOLFSSL_STM32_PKA | HW active | 924 keygen/s |
| RNG | STM32_RNG | HW active | 914 KiB/s |

### Software-Only Algorithms (confirmed by benchmark disparity)
| Algorithm | Benchmark | Notes |
|-----------|-----------|-------|
| SHA3-224/256/384/512 | 2.3-4.6 MiB/s | 10x slower than HW SHA-256 |
| HMAC-MD5 | 51 MiB/s | No MD5 in N6 HASH (STM32_NOMD5) |
| MD5 | 51 MiB/s | SW only, fast because MD5 is simple |
| ChaCha20-Poly1305 | 12-20 MiB/s | No HW support |
| RSA | SP math | No HW support |
| Ed25519/X25519 | ~11 ops/s | No HW support (see Ed25519 note below) |

**Ed25519 Performance Note (Cortex-M55)**: The ~11 ops/s figure (92-97ms per
operation) on a 600MHz M55 is notably low. The Cortex-M55 includes Helium (M-Profile
Vector Extension / MVE) which wolfSSL does not currently utilize — only generic
Thumb2 assembly is active (wolfcrypt/src/port/arm/thumb2-curve25519.S). Adding
Helium-optimized field arithmetic could yield significant speedups but requires
dedicated development effort. Flag as a future optimization opportunity if
Ed25519/X25519 performance is important for the use case.

---

## PHASE 2 — HMAC VALIDATION

### Step 1: Run Existing Tests
Run `wolfcrypt_test()` on the N6 target. The following HMAC tests will execute:
- `hmac_sha_test()` — SHA-1 HMAC, RFC 2202 vectors (test.c:8145+)
- `hmac_sha224_test()` — RFC 4231 vectors truncated to 28 bytes (test.c:8298+)
- `hmac_sha256_test()` — 5 vectors from RFC 4231 (test.c:8440+)
- `hmac_sha384_test()` — RFC 4231 vectors (test.c:8612+)
- `hmac_sha512_test()` — RFC 4231 vectors (test.c:8763+)
- `hmac_sha3_test()` — NIST CAVP vectors (test.c:8920+) — runs in SW

These tests already cover:
- Key shorter than block size (RFC 4231 test case 1: 20-byte key, 64-byte block)
- Key exactly at typical length (RFC 4231 test case 2: "Jefe")
- Key longer than block size (RFC 4231 test case 5: 131-byte key triggers pre-hash)
- Multi-byte messages of varying lengths
- Empty message (test case d in hmac_sha256_test: input=NULL, inLen=0)

### Step 2: Missing Test Coverage — Fill Gaps

**a) HMAC-SHA224** — `hmac_sha224_test()` already exists at test.c:8298. No action needed.

**b) HMAC-SHA1** — `hmac_sha_test()` exists (test.c:8145+) and uses WC_SHA type which
maps to HASH_AlgoSelection_SHA1 in GetAlgoInfo.
- Action: Verify test passes; no new code needed.

**c) Single-byte message HMAC** — Not explicitly tested in RFC 4231 vectors.
- Action: Add test case with `msg = {0x00}`, `msgLen = 1` for HMAC-SHA256.

**d) Message longer than one hash block (>64 bytes for SHA-256, >128 bytes for SHA-512)**
- RFC 4231 test case 3 already covers 50 bytes of 0xDD for SHA-256.
- Action: Add a 200-byte message test for SHA-512 (>128 byte block).

### Step 3: Root Cause Analysis Framework
If any HMAC test fails, check in order:
1. **Wrong digest output** → Check HASH_ALGOSELECTION_* value matches algorithm
2. **Timeout in WaitDataReady** → HASH peripheral not clocked (check STM32_HASH_CLOCK_ENABLE)
3. **Phase 2/3 hang** → DCAL bit not triggering; check HASH->STR write
4. **Key pre-hash failure** → Long key path in hmac.c:560-575 not using correct algo
5. **Re-key failure** → wc_Stm32_Hmac_SetKey after Final; context corruption

### Step 4: Code Review Status
No bugs identified by static code review of the HMAC hardware path. The
implementation correctly follows the STM32 HASH peripheral's 3-phase HMAC protocol.
Key pre-hashing and re-keying logic are sound.

**Hardware validation pending** — these findings must be confirmed by running all
HMAC test vectors on the N6 target. Code review alone cannot substitute for
on-target validation.

---

## PHASE 3 — FULL HARDWARE CRYPTO VALIDATION

### 3a. HASH Peripheral
Run `wolfcrypt_test()` — it includes NIST vector tests for all hash algorithms:
- `sha_test()` — SHA-1 NIST vectors
- `sha256_test()` — SHA-256 NIST FIPS 180-4 vectors (test.c:5092)
- `sha384_test()` — SHA-384 NIST vectors (test.c:5889)
- `sha512_test()` — SHA-512 NIST vectors (test.c:5349)
- `sha3_test()` — SHA3 NIST CAVP vectors (test.c:6613) — currently SW on N6

**Verification approach**: To confirm hardware path is taken (not silent SW fallback):
1. Compare benchmark numbers: HW SHA-256 should be ~47 MiB/s vs SW ~15 MiB/s
2. Or: temporarily define `DEBUG_STM32_HASH` to get printf traces from stm32.c

### 3b. SAES/CRYP (AES)

**Instance**: N6 uses `CRYP` instance (stm32.c:793), NOT `SAES` or `AES` remap.
Confirmed by working benchmarks at ~17 MiB/s.

**AES-CBC**: Tested by `aes_cbc_test()` in test.c with 128/256-bit keys.
**AES-GCM**: Tested by `aesgcm_test()` in test.c.

**AES-GCM AAD alignment (critical):**
- N6: `STM_CRYPT_HEADER_WIDTH = 4` (stm32.h:228) — AAD must be 4-byte aligned
- N6 is excluded from CRYP_HEADERWIDTHUNIT_BYTE exception (stm32.h:224-225)
- Non-aligned AAD triggers `useSwGhash = 1` (aes.c:9563-9568): hardware encrypts,
  software computes GHASH tag
- This is correct behavior, not a bug. Performance impact only for odd AAD sizes.
- Action: Run AES-GCM test with 1-byte, 3-byte, and 5-byte AAD to verify SW GHASH
  fallback produces correct tags.

**AES-CTR**: Should work via STM32_HAL_V2 `HAL_CRYP_Encrypt` with CTR mode.
Action: Verify `aesctr_test()` passes.

**AES-CCM**: No STM32 hardware acceleration path exists. AES-CCM is purely software
in wolfCrypt for STM32 targets — the CRYP peripheral only supports ECB, CBC, CTR,
and GCM modes (confirmed by code inspection of aes.c). The `aesccm_test()` exercises
the software implementation; no hardware path to verify.

### 3c. PKA (ECC)

**Configuration**: `WOLFSSL_STM32_PKA` enabled (default_conf.ftl:243).
`WOLFSSL_STM32_PKA_V2` NOT explicitly set but auto-detected via
`PKA_ECC_SCALAR_MUL_IN_B_COEFF` (stm32.c:81).

**Tests**: `ecc_test()` in test.c covers:
- `wc_ecc_make_key()` — P-256 key generation via PKA
- `wc_ecc_sign_hash() / wc_ecc_verify_hash()` — ECDSA
- `wc_ecc_shared_secret()` — ECDH

**Action**: Run `ecc_test()` and verify all sub-tests pass. Benchmarks already
confirm 924 keygen/s, 466 ECDHE/s, 180 sign/s, 168 verify/s.

**PKA V2 verification**: Check if N6 HAL defines `PKA_ECC_SCALAR_MUL_IN_B_COEFF`.
If yes, consider adding explicit `#define WOLFSSL_STM32_PKA_V2` in default_conf.ftl:243
for clarity (matching MP13 at line 234).

### 3d. RNG

**Tests**: `random_rng_test()` in test.c exercises `wc_RNG_GenerateBlock()`.
Benchmark confirms 914 KiB/s from hardware TRNG.

**Additional validation** (run on target):
- Call `wc_RNG_GenerateBlock()` 1000 times, verify no repeated 32-byte blocks
- Basic monobit test: generate 1MB, count 1-bits, verify within expected range.
  Per NIST SP800-22 Section 2.1 (Frequency/Monobit Test), for n=8,388,608 bits
  (1 MB), the expected count of 1-bits is ~4,194,304. The test statistic
  s_obs = |sum| / sqrt(n) should be < 2.576 for α=0.01 (two-tailed), giving
  an acceptance window of approximately ±7,451 bits. Use this threshold, not a
  tighter one — embedded TRNGs legitimately exhibit more variance than PRNGs,
  and a too-tight bound will false-flag healthy hardware.

---

## PHASE 4 — GAP ANALYSIS TABLE

| Algorithm | HAL Support on N6 | wolfCrypt HW Path | Status | Priority | Notes |
|-----------|------------------|-------------------|--------|----------|-------|
| SHA-1 | HASH peripheral | STM32_HASH | HW_VERIFIED | - | 48 MiB/s confirmed |
| SHA-224 | HASH peripheral | STM32_HASH_SHA2 | HW_VERIFIED | - | 47 MiB/s confirmed |
| SHA-256 | HASH peripheral | STM32_HASH_SHA2 | HW_VERIFIED | - | 47 MiB/s confirmed |
| SHA-384 | HASH peripheral | STM32_HASH_SHA384 | HW_VERIFIED | - | 49 MiB/s confirmed |
| SHA-512 | HASH peripheral | STM32_HASH_SHA512 | HW_VERIFIED | - | 49 MiB/s confirmed |
| SHA-512/224 | HASH peripheral | STM32_HASH_SHA512_224 | HW_VERIFIED | - | 49 MiB/s confirmed |
| SHA-512/256 | HASH peripheral | STM32_HASH_SHA512_256 | HW_VERIFIED | - | 49 MiB/s confirmed |
| **SHA3-224** | **HASH peripheral** | **NOT GATED for N6** | **GAP_HAL_EXISTS** | **HIGH** | See Gap #1 below |
| **SHA3-256** | **HASH peripheral** | **NOT GATED for N6** | **GAP_HAL_EXISTS** | **HIGH** | See Gap #1 below |
| **SHA3-384** | **HASH peripheral** | **NOT GATED for N6** | **GAP_HAL_EXISTS** | **HIGH** | See Gap #1 below |
| **SHA3-512** | **HASH peripheral** | **NOT GATED for N6** | **GAP_HAL_EXISTS** | **HIGH** | See Gap #1 below |
| HMAC-SHA1 | HASH HMAC mode | STM32_HMAC | HW_VERIFIED | - | 46 MiB/s confirmed |
| HMAC-SHA224 | HASH HMAC mode | STM32_HMAC | HW_VERIFIED | - | Test exists (test.c:8298) |
| HMAC-SHA256 | HASH HMAC mode | STM32_HMAC | HW_VERIFIED | - | 45 MiB/s confirmed |
| HMAC-SHA384 | HASH HMAC mode | STM32_HMAC | HW_VERIFIED | - | 46 MiB/s confirmed |
| HMAC-SHA512 | HASH HMAC mode | STM32_HMAC | HW_VERIFIED | - | 46 MiB/s confirmed |
| **HMAC-SHA3** | **HASH HMAC mode** | **NOT in GetAlgoInfo** | **GAP_HAL_EXISTS** | **MEDIUM** | See Gap #2 below |
| AES-CBC | CRYP peripheral | STM32_CRYPTO | HW_VERIFIED | - | ~17 MiB/s confirmed |
| AES-GCM | CRYP peripheral | STM32_CRYPTO_AES_GCM | HW_VERIFIED | - | ~16.5 MiB/s; AAD 4-byte align |
| AES-CTR | CRYP peripheral | STM32_CRYPTO | HW_UNVERIFIED | LOW | Run test to confirm |
| AES-CCM | none (CRYP N/A) | software only | SW_ONLY | - | CRYP supports ECB/CBC/CTR/GCM only |
| AES-XTS | none | none | SW_ONLY | - | Not supported by CRYP peripheral |
| ECC P-256 | PKA | WOLFSSL_STM32_PKA | HW_VERIFIED | - | 924 keygen/s confirmed |
| ECC P-384 | PKA | WOLFSSL_STM32_PKA | HW_UNVERIFIED | MEDIUM | Test if HAVE_ECC384 works with PKA |
| ECDH | PKA | WOLFSSL_STM32_PKA | HW_VERIFIED | - | 466 agree/s confirmed |
| RSA | none on N6 | software (SP math) | SW_ONLY | - | 430 pub/s, 13 priv/s |
| ChaCha20-Poly1305 | none | software | SW_ONLY | - | 12 MiB/s |
| Ed25519/X25519 | none | software (Thumb2 asm) | SW_ONLY | - | ~11 ops/s; no Helium/MVE opt |
| **SHAKE128/256** | **HASH peripheral** | **NOT dispatched to HW** | **GAP_CODE_EXISTS** | **HIGH** | See Gap #5 below |
| ML-KEM-512/768/1024 | none (SW only) | wolfcrypt kyber.c | SW_ONLY | - | Pure C + Thumb2 NTT asm |
| ML-DSA-44/65/87 | none (SW only) | wolfcrypt dilithium.c | SW_ONLY | - | Pure C, no Thumb2 asm yet |
| SLH-DSA | none | not in wolfCrypt yet | GAP_NO_HAL | LOW | Future standard |

### Gap #1 (HIGH): SHA3 Hardware Not Enabled for N6

**File**: `wolfssl/wolfcrypt/port/st/stm32.h` line 53-55

**Current code**:
```c
#if defined(WOLFSSL_STM32MP13)
    #define STM32_HASH_SHA3
#endif
```

**Required change**: Add N6 to the conditional (safe — compiles only if HAL has SHA3):
```c
#if defined(WOLFSSL_STM32MP13) || defined(WOLFSSL_STM32N6)
    #define STM32_HASH_SHA3
#endif
```

**Safety**: If the N6 HAL lacks `HASH_ALGOSELECTION_SHA3_*`, the build will fail
at compile time in `Stm32GetAlgo()` (sha3.c:935-948) where these constants are
used — this is a safe, loud failure. If it compiles, the HAL supports SHA3.
No runtime risk.

**Cascading effects** (all automatic, no additional changes needed):
- `STM32_HASH_FIFO_SIZE` → 36 (from 32) — stm32.h:103
- `STM32_HASH_Context` gains `SHA3CFGR` field — stm32.h:118
- Context save/restore includes SHA3CFGR — stm32.c:152-154, 197-199
- `sha3.c` uses hardware path at line 918 instead of software Keccak

**Important**: This does NOT automatically benefit SHAKE128/256 — see Gap #5.

**Expected performance improvement**: SHA3-256 from 4.4 MiB/s → ~20-45 MiB/s

**Effort**: Small (S) — 1 line change, well-tested pattern from MP13

### Gap #2 (MEDIUM): HMAC-SHA3 Not in Hardware HMAC

**File**: `wolfcrypt/src/port/st/stm32.c` line 447-501

**Issue**: `wc_Stm32_Hmac_GetAlgoInfo()` has no cases for WC_SHA3_224/256/384/512.
HMAC-SHA3 falls through to software ipad/opad. Even after Gap #1 fix, HMAC-SHA3
would use software ipad/opad over HARDWARE SHA3 (still an improvement).

**For full HW HMAC-SHA3**: Add SHA3 cases to `wc_Stm32_Hmac_GetAlgoInfo()`:
```c
#if defined(STM32_HASH_SHA3) && defined(WOLFSSL_SHA3)
    #ifndef WOLFSSL_NOSHA3_224
    case WC_SHA3_224:
        if (algo)       *algo = HASH_ALGOSELECTION_SHA3_224;
        if (blockSize)  *blockSize = WC_SHA3_224_BLOCK_SIZE;
        if (digestSize) *digestSize = WC_SHA3_224_DIGEST_SIZE;
        break;
    #endif
    // ... SHA3-256, SHA3-384, SHA3-512 similarly
#endif
```

**Prerequisite (critical)**: The STM32 HASH peripheral's 3-phase HMAC mode
(key → message → key) may only work with MD5/SHA-1/SHA-2 algo selections on
some STM32 parts. Before implementing this change:

1. **Check RM0486** (STM32N6 Reference Manual), HASH chapter, "HMAC mode"
   section. Confirm that the HMAC mode description lists SHA3 as a supported
   algorithm for HMAC operations, not just for hash operations.
2. **Check the HAL**: Verify that `HASH_ALGOSELECTION_SHA3_*` constants are
   accepted by `HAL_HASH_Init()` when `HASH_ALGOMODE_HMAC` is set in the
   HASH_CR register.
3. **Fallback plan**: If the HASH peripheral does NOT support SHA3 in HMAC mode,
   the software ipad/opad path with hardware SHA3 (from Gap #1) is still a
   worthwhile improvement. In that case, do NOT add the SHA3 cases to
   GetAlgoInfo — leave them falling to the `default: BAD_FUNC_ARG` path which
   triggers the software HMAC over hardware hash path.

**Effort**: Medium (M) — need hardware manual verification before coding

### Gap #3 (LOW): PKA_V2 Explicit Define for N6

**File**: `IDE/STM32Cube/default_conf.ftl` line 238-246

**Issue**: MP13 explicitly defines `WOLFSSL_STM32_PKA_V2` (line 234) but N6 does not.
Auto-detection at stm32.c:81 handles this at compile time — if the N6 HAL defines
`PKA_ECC_SCALAR_MUL_IN_B_COEFF`, PKA_V2 is auto-enabled. No runtime risk either way.

**Action**: Defer — auto-detection is sufficient. If we later confirm V2 support,
add explicit `#define WOLFSSL_STM32_PKA_V2` for documentation clarity.

**Effort**: Small (S) — 1 line, deferred

### Gap #4 (RESOLVED): Missing HMAC-SHA224 Test

`hmac_sha224_test()` already exists at test.c:8298-8435 with RFC 4231 vectors
truncated to 28-byte digest. No action needed — this was a false gap in the
original analysis.

### Gap #5 (HIGH): SHAKE128/256 Not Dispatched to Hardware

**File**: `wolfcrypt/src/sha3.c`

**Issue**: After Gap #1 is fixed (STM32_HASH_SHA3 enabled for N6), SHA3-224/256/384/512
hash operations use the hardware path. However, SHAKE128/256 (XOF — eXtendable
Output Function) does NOT use the hardware path. Investigation reveals:

- `wc_InitShake256()` (sha3.c:1916) calls `wc_InitSha3()` which does pick up the
  hardware init when STM32_HASH_SHA3 is defined.
- But `wc_Shake256_Update()` and `wc_Shake256_Final()` call `Sha3Update()`/`Sha3Final()`
  (software local functions), NOT the hardware-dispatched `wc_Sha3Update()`.
- The SHAKE functions are defined OUTSIDE the `#if defined(STM32_HASH_SHA3)` / `#else`
  preprocessor block, so they always use the software Keccak path.
- Additionally, SHAKE uses padding byte 0x1F vs SHA3's 0x06 — the HASH peripheral's
  SHA3 mode uses fixed SHA3 padding, and it is unclear whether the peripheral can
  be configured for SHAKE's domain-separated padding.

**Why this matters**: SHAKE256 is the core XOF inside both ML-KEM (FIPS 203) and
ML-DSA (FIPS 204). Every keygen, encapsulation, and signing operation performs
multiple SHAKE calls. If SHAKE stays in software while SHA3 moves to hardware,
post-quantum algorithm performance will NOT benefit from Gap #1.

**Investigation needed**:
1. Check RM0486 HASH chapter for XOF/SHAKE support. Does the HASH peripheral
   have a SHAKE mode or an XOF output mode?
2. If the peripheral supports SHAKE natively (separate algo selection constant
   or a configurable padding byte), add SHAKE dispatch similar to SHA3.
3. If the peripheral does NOT support SHAKE directly, explore whether the
   Keccak permutation can be offloaded to hardware with manual padding/squeezing
   in software. This is architecturally complex and may not be worthwhile.
4. **Fallback**: If SHAKE cannot use hardware at all, document this as a known
   limitation. Post-quantum performance on N6 will be bounded by software
   Keccak throughput (~4 MiB/s) regardless of SHA3 hardware availability.

**Effort**: Medium-Large (M-L) — requires hardware manual research + potentially
nontrivial code changes to SHAKE dispatch

---

## PHASE 5 — BENCHMARK PLAN

### Current Baseline (from STM32_Benchmarks.md:1388-1445)
Already captured with HW crypto enabled. Key numbers:
- AES-CBC-128: 17.6 MiB/s | AES-GCM-128: 16.6 MiB/s
- SHA-256: 47 MiB/s | SHA-512: 49 MiB/s | SHA3-256: 4.4 MiB/s (SW!)
- HMAC-SHA256: 44.6 MiB/s | HMAC-SHA512: 45.7 MiB/s
- ECC P-256 keygen: 924 ops/s | sign: 180 ops/s | verify: 168 ops/s

### New Benchmarks Needed (after Gap #1 fix)
| Algorithm | Before (SW) | Expected After (HW) | Source |
|-----------|-------------|---------------------|--------|
| SHA3-224 | 4.6 MiB/s | ~25-40 MiB/s | HASH peripheral |
| SHA3-256 | 4.4 MiB/s | ~25-40 MiB/s | HASH peripheral |
| SHA3-384 | 3.4 MiB/s | ~20-35 MiB/s | HASH peripheral |
| SHA3-512 | 2.3 MiB/s | ~15-25 MiB/s | HASH peripheral |

### Comparison Table Template (fill on target)
```
Algorithm          | HW (MiB/s) | SW (MiB/s) | Speedup
-------------------+------------+------------+--------
SHA-1              |     48     |     --     |   --
SHA-256            |     47     |    ~15     |  ~3.1x
SHA-384            |     49     |    ~12     |  ~4.1x
SHA-512            |     49     |    ~12     |  ~4.1x
SHA3-256           |   TBD(HW)  |    4.4     |  TBD
AES-CBC-128        |    17.6    |    ~6      |  ~2.9x
AES-GCM-128        |    16.6    |    ~5      |  ~3.3x
HMAC-SHA256        |    44.6    |    ~14     |  ~3.2x
ECC P-256 keygen   |    924/s   |   ~30/s    |  ~31x
ML-KEM-512 keygen  |   TBD/s   |     --     |  SW only
ML-KEM-512 encap   |   TBD/s   |     --     |  SW only
ML-KEM-512 decap   |   TBD/s   |     --     |  SW only
ML-KEM-768 keygen  |   TBD/s   |     --     |  SW only
ML-KEM-768 encap   |   TBD/s   |     --     |  SW only
ML-KEM-768 decap   |   TBD/s   |     --     |  SW only
ML-KEM-1024 keygen |   TBD/s   |     --     |  SW only
ML-KEM-1024 encap  |   TBD/s   |     --     |  SW only
ML-KEM-1024 decap  |   TBD/s   |     --     |  SW only
ML-DSA-44 keygen   |   TBD/s   |     --     |  SW only
ML-DSA-44 sign     |   TBD/s   |     --     |  SW only
ML-DSA-44 verify   |   TBD/s   |     --     |  SW only
ML-DSA-65 keygen   |   TBD/s   |     --     |  SW only
ML-DSA-65 sign     |   TBD/s   |     --     |  SW only
ML-DSA-65 verify   |   TBD/s   |     --     |  SW only
ML-DSA-87 keygen   |   TBD/s   |     --     |  SW only
ML-DSA-87 sign     |   TBD/s   |     --     |  SW only
ML-DSA-87 verify   |   TBD/s   |     --     |  SW only
```

Reference comparison (STM32F439ZI Cortex-M4 @ 168MHz, SW only, from wolfSSL blog):
- ML-KEM-512 keygen: 248 ops/s | encap: 262 ops/s | decap: 198 ops/s
- ML-KEM-768 keygen: 153 ops/s
The N6 at 600MHz with M55 + Thumb2 NTT asm should substantially beat these.
Flag any result that doesn't.

SW baselines can be obtained by adding `#define NO_STM32_HASH`, `#define NO_STM32_CRYPTO`
to user_settings.h and re-running benchmarks (ARM ASM baselines already in
STM32_Benchmarks.md:1448-1513).

### Stack Size Baseline

**Current defaults**: `WOLF_EXAMPLES_STACK` = 30KB (wolfssl_example.h:43),
FreeRTOS task recommended at 8960 bytes (IDE/STM32Cube/README.md).

**Action**: Before running PQ tests (Phase 6), measure FreeRTOS high-water mark
for each wolfCrypt task using `uxTaskGetStackHighWaterMark()`. Document the
baseline stack consumption for hash/HMAC/AES/ECC operations so that PQ stack
requirements can be compared against known headroom.

---

## PHASE 6 — POST-QUANTUM ALGORITHM VALIDATION

### Prerequisites (check first)
Inspect user_settings.h for the following defines. If absent, add them and note
that they were missing — this itself is a finding:

```c
#define WOLFSSL_HAVE_KYBER        /* ML-KEM (FIPS 203) */
#define WOLFSSL_ML_KEM
#define WOLFSSL_KYBER512
#define WOLFSSL_KYBER768
#define WOLFSSL_KYBER1024

#define HAVE_DILITHIUM            /* ML-DSA (FIPS 204) */
#define WOLFSSL_ML_DSA
#define WOLFSSL_DILITHIUM_LEVEL2
#define WOLFSSL_DILITHIUM_LEVEL3
#define WOLFSSL_DILITHIUM_LEVEL5
```

Also check for Thumb2/M4 assembly optimizations — these give 2-3x speedup on
Cortex-M55 and should be enabled:
```c
#define WOLFSSL_HAVE_SP_ARM_THUMB  /* (or equivalent for Kyber NTT) */
```

**Current ASM status** (confirmed by code inspection):
- ML-KEM NTT: Thumb2 assembly EXISTS at `wolfcrypt/src/port/arm/thumb2-mlkem-asm.S`
  (81KB, full NTT pipeline). Verify it is being compiled for the N6 build.
- ML-DSA: NO Thumb2 assembly optimizations exist. Pure C only. This is a known
  limitation that affects sign performance.
- SHAKE256 (used by both ML-KEM and ML-DSA): Software only — see Gap #5.

### 6a. Stack Size Audit (do before running any PQ tests)

ML-DSA-87 private key is 4912 bytes. ML-DSA-87 signature is 4627 bytes.
These live on the stack during sign/verify unless the caller pre-allocates.
Measure current FreeRTOS task stack high-water mark, then determine the
minimum stack required for each PQ operation:

- `wc_MlKemKey_MakeKey()` — note peak stack consumption
- `wc_MlKemKey_Encapsulate()` — note peak stack consumption
- `wc_MlKemKey_Decapsulate()` — note peak stack consumption
- `wc_MlDsaKey_MakeKey()` — note peak stack consumption
- `wc_MlDsaKey_Sign()` — note peak stack consumption (ML-DSA-87: largest)
- `wc_MlDsaKey_Verify()` — note peak stack consumption

If the task stack is < 12KB, PQ sign operations will likely crash silently.
Document the minimum required stack size for each parameter set.

### 6b. Correctness Tests

Run the existing wolfCrypt PQ tests:
- `mlkem_test()` — EXISTS at test.c:46715, called at test.c:2787
- `dilithium_test()` — EXISTS at test.c:50450, called at test.c:2794

If these tests are not wired into the N6 build (missing defines), note it as
a finding and ensure the prerequisite defines above are added.

For additional round-trip validation beyond the existing tests:

For ML-KEM (each parameter set 512/768/1024):
1. `wc_MlKemKey_Init()` + `wc_MlKemKey_MakeKey()` — keygen
2. `wc_MlKemKey_Encapsulate()` — Alice produces ct + ss
3. `wc_MlKemKey_Decapsulate()` — Bob recovers ss from ct
4. Assert ss_alice == ss_bob byte-for-byte
5. Test decapsulation with corrupted ciphertext — ss must differ (FO transform)

For ML-DSA (each level 2/3/5):
1. `wc_MlDsaKey_Init()` + `wc_MlDsaKey_MakeKey()` — keygen
2. `wc_MlDsaKey_Sign()` on a 32-byte message hash
3. `wc_MlDsaKey_Verify()` — must return success
4. Flip one bit in the signature — verify must return failure
5. Flip one bit in the message — verify must return failure

Use NIST ACVP Known Answer Test vectors where available.

### 6c. SHA3/SHAKE Hardware Benefit Measurement

ML-KEM and ML-DSA both use SHAKE256 internally as a XOF. After Gap #1 is fixed
(STM32_HASH_SHA3 enabled for N6), measure whether PQ performance improves:

- Run ML-KEM-768 keygen benchmark before Gap #1 fix (SHA3 in SW)
- Apply Gap #1 fix, rebuild
- Run ML-KEM-768 keygen benchmark after (SHA3 through HW? See below)
- Compare ops/sec

**Critical caveat**: Per Gap #5, SHAKE128/256 does NOT currently dispatch to
hardware even when STM32_HASH_SHA3 is enabled. The SHAKE code path in sha3.c
bypasses the STM32 hardware dispatch entirely. Therefore:

- If Gap #1 alone does NOT improve PQ performance (expected outcome), this
  confirms Gap #5 is the bottleneck.
- Check whether `wc_InitShake256()` → `wc_InitSha3()` picks up hardware init
  but `wc_Shake256_Update()`/`wc_Shake256_Final()` still uses software Keccak.
- If SHAKE hardware path cannot be enabled (see Gap #5 investigation), PQ
  algorithms will remain bounded by software Keccak throughput regardless of
  SHA3 hardware availability.

### 6d. PQ Benchmark (add to Phase 5 table)

Run `wolfcrypt_benchmark()` with PQ algorithms enabled. Record ops/sec for each
parameter set, both before and after the SHA3 HW fix. Add to the benchmark
comparison table:

```
Algorithm             | Before Gap#1 (SW SHA3) | After Gap#1 (HW SHA3) | Notes
----------------------+------------------------+-----------------------+------
ML-KEM-512  keygen    |         ops/s          |         ops/s         |
ML-KEM-512  encap     |         ops/s          |         ops/s         |
ML-KEM-512  decap     |         ops/s          |         ops/s         |
ML-KEM-768  keygen    |         ops/s          |         ops/s         |
ML-KEM-768  encap     |         ops/s          |         ops/s         |
ML-KEM-768  decap     |         ops/s          |         ops/s         |
ML-KEM-1024 keygen    |         ops/s          |         ops/s         |
ML-DSA-44   keygen    |         ops/s          |         ops/s         |
ML-DSA-44   sign      |         ops/s          |         ops/s         |
ML-DSA-44   verify    |         ops/s          |         ops/s         |
ML-DSA-65   sign      |         ops/s          |         ops/s         |
ML-DSA-87   sign      |         ops/s          |         ops/s         |
```

Reference comparison (STM32F439ZI Cortex-M4 @ 168MHz, SW only, from wolfSSL blog):
- ML-KEM-512 keygen: 248 ops/s | encap: 262 ops/s | decap: 198 ops/s
- ML-KEM-768 keygen: 153 ops/s
The N6 at 600MHz with M55 + Thumb2 NTT asm should substantially beat these.
Flag any result that doesn't.

**ML-DSA performance note**: No Thumb2 assembly optimizations exist for ML-DSA
in wolfCrypt. If ML-DSA sign performance is inadequate for the use case, flag as
a candidate for future Thumb2 asm optimization work (following the pattern of
`thumb2-mlkem-asm.S`).

---

## IMPLEMENTATION STEPS (ordered)

### 1. HIGH: Enable SHA3 Hardware for N6
- **File**: `wolfssl/wolfcrypt/port/st/stm32.h:53-55`
- **Change**: Add `|| defined(WOLFSSL_STM32N6)` to STM32_HASH_SHA3 conditional
- **Safety**: If N6 HAL lacks SHA3 algo defines, build fails at compile time (safe)
- **Verify**: Rebuild for N6 target. If it compiles: run `sha3_test()`, benchmark SHA3

### 2. MEDIUM: Add HMAC-SHA3 to Hardware HMAC (if HMAC mode supports SHA3)
- **File**: `wolfcrypt/src/port/st/stm32.c:447-501`
- **Change**: Add WC_SHA3_* cases to `wc_Stm32_Hmac_GetAlgoInfo()`
- **Prerequisite**: Check RM0486 HASH chapter, HMAC mode section — verify SHA3 is
  listed as a supported algorithm for 3-phase HMAC. If not supported, do NOT add
  the cases; software HMAC over hardware SHA3 (from Step 1) is the correct fallback.
- **Verify**: Run `hmac_sha3_test()`

### 3. HIGH: Investigate SHAKE Hardware Dispatch (Gap #5)
- **File**: `wolfcrypt/src/sha3.c` — SHAKE128/256 functions
- **Investigation**: Check RM0486 for SHAKE/XOF support in HASH peripheral
- **If supported**: Add SHAKE dispatch to hardware within the STM32_HASH_SHA3 block
- **If not supported**: Document as known limitation; PQ perf bounded by SW Keccak

### 4. LOW: Add edge-case HMAC test vectors
- **File**: `wolfcrypt/test/test.c`
- **Change**: Add single-byte message test to `hmac_sha256_test()`,
  200-byte message test to `hmac_sha512_test()`

### 5. LOW: Add PKA_V2 explicit define for N6 (deferred)
- **File**: `IDE/STM32Cube/default_conf.ftl:243`
- **Change**: Deferred — auto-detection at stm32.c:81 handles both V1/V2 at compile time

### 6. MEDIUM: Stack size audit for PQ algorithms
- **Action**: Measure FreeRTOS high-water marks before/after PQ operations
- **Document**: Minimum stack sizes per PQ parameter set
- **Critical**: If default task stack < 12KB, PQ operations may stack-overflow silently

### 7. LOW: Enable and benchmark PQ algorithms
- **Action**: Add ML-KEM/ML-DSA defines to user_settings.h if missing
- **Verify**: Run `mlkem_test()` and `dilithium_test()` on N6 target
- **Benchmark**: Record ops/sec for all PQ parameter sets

---

## VERIFICATION CHECKLIST

On-target (STM32N6 board):
- [ ] `wolfcrypt_test()` passes all tests (hash, HMAC, AES, ECC, RNG)
- [ ] SHA3 test passes with HW acceleration (after Step 1)
- [ ] HMAC-SHA256 with RFC 4231 vectors — all 5 pass
- [ ] HMAC-SHA384/512 with RFC 4231 vectors — pass
- [ ] HMAC-SHA3 with NIST CAVP vectors — pass (SW or HW depending on Step 2)
- [ ] AES-GCM with non-aligned AAD (1,3,5 bytes) — correct tags
- [ ] ECC P-256 sign then verify round-trip
- [ ] ECC ECDH shared secret matches known vector
- [ ] RNG 1000x GenerateBlock — no repeats
- [ ] RNG monobit test — 1MB, acceptance window per NIST SP800-22 (±7,451 bits)
- [ ] Benchmark SHA3 before/after Gap #1 fix — confirm HW speedup
- [ ] Benchmark all algorithms with HW enabled vs disabled
- [ ] FreeRTOS stack high-water marks recorded for all crypto operations
- [ ] ML-KEM round-trip (keygen → encap → decap → shared secret match) — all parameter sets
- [ ] ML-DSA round-trip (keygen → sign → verify) — all levels
- [ ] ML-DSA negative tests (corrupted sig/msg → verify fails) — all levels
- [ ] PQ stack consumption documented per parameter set
- [ ] PQ benchmarks recorded, compared against F439ZI M4 reference numbers

Code-only (no hardware needed):
- [ ] All compile guards are correct for WOLFSSL_STM32N6
- [ ] HMAC GetAlgoInfo covers SHA1/224/256/384/512 (and SHA3 after Step 2, if supported)
- [ ] Context save/restore sizes match HASH_CR_SIZE=103
- [ ] AES init uses correct CRYP instance (not SAES)
- [ ] PKA auto-detection logic is sound
- [ ] SHAKE dispatch path traced — confirm whether HW or SW after Gap #1
- [ ] PQ defines present in user_settings.h (or documented as missing)
- [ ] Thumb2 ML-KEM NTT assembly compiled into N6 build
- [ ] ML-DSA has no Thumb2 asm — documented as known limitation

---

## DELIVERABLES SUMMARY

1. **PASS/FAIL Table**: Run wolfcrypt_test() — every algorithm result recorded
2. **Gap Analysis Table**: Phase 4 table above (complete, with PQ additions)
3. **Stack Size Report**: FreeRTOS high-water marks for classical and PQ operations
4. **Benchmark Comparison**: HW vs SW for all algorithms, PQ before/after SHA3 HW
5. **Recommended Next Steps**:
   - HIGH: SHA3 HW enable (1-line fix, ~10x SHA3 speedup)
   - HIGH: SHAKE HW investigation (critical for PQ performance)
   - MEDIUM: HMAC-SHA3 HW HMAC (if HASH HMAC mode supports SHA3 per RM0486)
   - MEDIUM: Stack size audit for PQ (crash risk if < 12KB)
   - LOW: PKA_V2 explicit define, edge-case HMAC vectors, PQ benchmarks
