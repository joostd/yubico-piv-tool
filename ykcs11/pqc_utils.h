/*
 * Copyright (c) 2024 Yubico AB
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

#ifndef PQC_UTILS_H
#define PQC_UTILS_H

#include "ykcs11.h"

// NIST OID Length (all PQC OIDs are 11 bytes when DER-encoded)
#define PQC_OID_LENGTH 11

// NIST OIDs for ML-DSA parameter sets (DER-encoded)
// OID 2.16.840.1.101.3.4.3.17 (ML-DSA-44)
extern const CK_BYTE MLDSA44_OID[PQC_OID_LENGTH];
// OID 2.16.840.1.101.3.4.3.18 (ML-DSA-65)
extern const CK_BYTE MLDSA65_OID[PQC_OID_LENGTH];
// OID 2.16.840.1.101.3.4.3.19 (ML-DSA-87)
extern const CK_BYTE MLDSA87_OID[PQC_OID_LENGTH];

// NIST OIDs for ML-KEM parameter sets (DER-encoded)
// OID 2.16.840.1.101.3.4.4.1 (ML-KEM-512)
extern const CK_BYTE MLKEM512_OID[PQC_OID_LENGTH];
// OID 2.16.840.1.101.3.4.4.2 (ML-KEM-768)
extern const CK_BYTE MLKEM768_OID[PQC_OID_LENGTH];
// OID 2.16.840.1.101.3.4.4.3 (ML-KEM-1024)
extern const CK_BYTE MLKEM1024_OID[PQC_OID_LENGTH];

/**
 * Map PKCS#11 CKA_PARAMETER_SET OID to PIV algorithm ID
 *
 * @param oid Pointer to DER-encoded OID bytes
 * @param oid_len Length of OID in bytes
 * @return PIV algorithm ID (0xE2-0xE7), or 0 if unknown/invalid
 */
unsigned char oid_to_piv_algorithm(const CK_BYTE *oid, CK_ULONG oid_len);

/**
 * Map PIV algorithm ID to PKCS#11 CKA_PARAMETER_SET OID
 *
 * @param algorithm PIV algorithm ID (0xE2-0xE7)
 * @param oid_len Output: length of OID in bytes
 * @return Pointer to DER-encoded OID, or NULL if unknown/invalid
 */
const CK_BYTE* piv_algorithm_to_oid(unsigned char algorithm, CK_ULONG *oid_len);

/**
 * Get public key size for a PIV PQC algorithm
 *
 * @param algorithm PIV algorithm ID (0xE2-0xE7)
 * @return Public key size in bytes, or 0 if unknown
 */
size_t pqc_get_public_key_size(unsigned char algorithm);

/**
 * Detect PIV algorithm by public key size
 *
 * @param pubkey_len Public key size in bytes
 * @return PIV algorithm ID (0xE2-0xE7), or 0 if not a recognized PQC size
 */
unsigned char pqc_detect_algorithm_by_size(size_t pubkey_len);

/**
 * Get PKCS#11 key type for a PIV PQC algorithm
 *
 * @param algorithm PIV algorithm ID (0xE2-0xE7)
 * @return CKK_ML_DSA or CKK_ML_KEM, or CK_UNAVAILABLE_INFORMATION if unknown
 */
CK_KEY_TYPE pqc_get_key_type(unsigned char algorithm);

#endif /* PQC_UTILS_H */
