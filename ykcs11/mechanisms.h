/*
 * Copyright (c) 2015-2016,2019-2020 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef MECHANISMS_H
#define MECHANISMS_H

#include "ykcs11.h"

// PKCS#11 v3.2 Post-Quantum Cryptography mechanisms
// Specification: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html
#ifndef CKM_ML_DSA_KEY_PAIR_GEN
#define CKM_ML_DSA_KEY_PAIR_GEN        0x0000001cUL  // ML-DSA key pair generation (generic)
#define CKM_ML_DSA                     0x0000001dUL  // ML-DSA sign/verify
#define CKM_HASH_ML_DSA_SHA256         0x00000024UL  // Hash-then-sign with SHA-256
#define CKM_HASH_ML_DSA_SHA512         0x00000026UL  // Hash-then-sign with SHA-512
#define CKM_ML_KEM_KEY_PAIR_GEN        0x0000000fUL  // ML-KEM key pair generation (generic)
#define CKM_ML_KEM                     0x00000017UL  // ML-KEM encapsulate/decapsulate
#define CKK_ML_DSA                     0x0000004aUL  // ML-DSA key type
#define CKK_ML_KEM                     0x00000049UL  // ML-KEM key type
#define CKA_PARAMETER_SET              0x0000061dUL  // Parameter set selection (CK_ULONG)

// CKA_PARAMETER_SET values. PKCS#11 v3.2 types these as CK_ML_DSA_PARAMETER_SET_TYPE
// / CK_ML_KEM_PARAMETER_SET_TYPE, both CK_ULONG, so the value is a small enum and
// not the DER-encoded NIST OID.
#define CKP_ML_DSA_44                  0x00000001UL
#define CKP_ML_DSA_65                  0x00000002UL
#define CKP_ML_DSA_87                  0x00000003UL
#define CKP_ML_KEM_512                 0x00000001UL
#define CKP_ML_KEM_768                 0x00000002UL
#define CKP_ML_KEM_1024                0x00000003UL

// CK_MECHANISM_INFO flags added by PKCS#11 v3.2 for key encapsulation. Both are
// reported by CKM_ML_KEM.
#define CKF_ENCAPSULATE                0x10000000UL
#define CKF_DECAPSULATE                0x20000000UL

// Key object attributes added by PKCS#11 v3.2. Distinct from the mechanism flags
// above: these describe what an individual key may be used for. v3.2 sections 5.18.8
// and 5.18.9 make CKA_ENCAPSULATE / CKA_DECAPSULATE = CK_TRUE a precondition of
// C_EncapsulateKey / C_DecapsulateKey.
#define CKA_ENCAPSULATE                0x00000633UL
#define CKA_DECAPSULATE                0x00000634UL
#endif

CK_RV sign_mechanism_init(ykcs11_session_t *session, ykcs11_pkey_t *key, CK_MECHANISM_PTR mech);
CK_RV sign_mechanism_final(ykcs11_session_t *session, CK_BYTE_PTR sig, CK_ULONG_PTR sig_len);
CK_RV sign_mechanism_cleanup(ykcs11_session_t *session);

CK_RV verify_mechanism_init(ykcs11_session_t *session, ykcs11_pkey_t *key, CK_MECHANISM_PTR mech);
CK_RV verify_mechanism_final(ykcs11_session_t *session, CK_BYTE_PTR sig, CK_ULONG sig_len);
CK_RV verify_mechanism_cleanup(ykcs11_session_t *session);

CK_RV check_generation_mechanism(CK_MECHANISM_PTR m);
CK_RV validate_derive_key_attribute(CK_ATTRIBUTE_TYPE type, void *value);

CK_RV digest_mechanism_init(ykcs11_session_t *session, CK_MECHANISM_PTR mech);
CK_RV digest_mechanism_update(ykcs11_session_t *session, CK_BYTE_PTR in, CK_ULONG in_len);
CK_RV digest_mechanism_final(ykcs11_session_t *session, CK_BYTE_PTR pDigest, CK_ULONG_PTR pDigestLength);

CK_RV decrypt_mechanism_init(ykcs11_session_t *session, ykcs11_pkey_t *key, CK_MECHANISM_PTR mech);
CK_RV decrypt_mechanism_final(ykcs11_session_t *session, CK_BYTE_PTR dec, CK_ULONG_PTR dec_len, CK_ULONG key_len);

#endif
