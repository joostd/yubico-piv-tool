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

#include "pqc_utils.h"
#include "mechanisms.h"
#include "../lib/ykpiv.h"
#include <string.h>

// NIST OIDs for ML-DSA parameter sets (DER-encoded)
// Format: 06 0B (OID tag + length) + OID bytes

// OID 2.16.840.1.101.3.4.3.17 (ML-DSA-44)
const CK_BYTE MLDSA44_OID[PQC_OID_LENGTH] = {
  0x06, 0x0B,                                     // OID tag + length
  0x60, 0x86, 0x48, 0x01, 0x65,                  // 2.16.840.1.101
  0x03, 0x04, 0x03, 0x11                         // .3.4.3.17
};

// OID 2.16.840.1.101.3.4.3.18 (ML-DSA-65)
const CK_BYTE MLDSA65_OID[PQC_OID_LENGTH] = {
  0x06, 0x0B,
  0x60, 0x86, 0x48, 0x01, 0x65,
  0x03, 0x04, 0x03, 0x12                         // .3.4.3.18
};

// OID 2.16.840.1.101.3.4.3.19 (ML-DSA-87)
const CK_BYTE MLDSA87_OID[PQC_OID_LENGTH] = {
  0x06, 0x0B,
  0x60, 0x86, 0x48, 0x01, 0x65,
  0x03, 0x04, 0x03, 0x13                         // .3.4.3.19
};

// NIST OIDs for ML-KEM parameter sets (DER-encoded)

// OID 2.16.840.1.101.3.4.4.1 (ML-KEM-512)
const CK_BYTE MLKEM512_OID[PQC_OID_LENGTH] = {
  0x06, 0x0B,
  0x60, 0x86, 0x48, 0x01, 0x65,
  0x03, 0x04, 0x04, 0x01                         // .3.4.4.1
};

// OID 2.16.840.1.101.3.4.4.2 (ML-KEM-768)
const CK_BYTE MLKEM768_OID[PQC_OID_LENGTH] = {
  0x06, 0x0B,
  0x60, 0x86, 0x48, 0x01, 0x65,
  0x03, 0x04, 0x04, 0x02                         // .3.4.4.2
};

// OID 2.16.840.1.101.3.4.4.3 (ML-KEM-1024)
const CK_BYTE MLKEM1024_OID[PQC_OID_LENGTH] = {
  0x06, 0x0B,
  0x60, 0x86, 0x48, 0x01, 0x65,
  0x03, 0x04, 0x04, 0x03                         // .3.4.4.3
};

unsigned char oid_to_piv_algorithm(const CK_BYTE *oid, CK_ULONG oid_len) {
  if (oid == NULL || oid_len != PQC_OID_LENGTH) {
    return 0;
  }

  // Compare against all known OIDs
  if (memcmp(oid, MLDSA44_OID, PQC_OID_LENGTH) == 0) {
    return YKPIV_ALGO_MLDSA44;   // 0xE2
  }
  if (memcmp(oid, MLDSA65_OID, PQC_OID_LENGTH) == 0) {
    return YKPIV_ALGO_MLDSA65;   // 0xE3
  }
  if (memcmp(oid, MLDSA87_OID, PQC_OID_LENGTH) == 0) {
    return YKPIV_ALGO_MLDSA87;   // 0xE4
  }
  if (memcmp(oid, MLKEM512_OID, PQC_OID_LENGTH) == 0) {
    return YKPIV_ALGO_MLKEM512;  // 0xE5
  }
  if (memcmp(oid, MLKEM768_OID, PQC_OID_LENGTH) == 0) {
    return YKPIV_ALGO_MLKEM768;  // 0xE6
  }
  if (memcmp(oid, MLKEM1024_OID, PQC_OID_LENGTH) == 0) {
    return YKPIV_ALGO_MLKEM1024; // 0xE7
  }

  return 0;  // Unknown OID
}

const CK_BYTE* piv_algorithm_to_oid(unsigned char algorithm, CK_ULONG *oid_len) {
  if (oid_len != NULL) {
    *oid_len = PQC_OID_LENGTH;
  }

  switch (algorithm) {
    case YKPIV_ALGO_MLDSA44:
      return MLDSA44_OID;
    case YKPIV_ALGO_MLDSA65:
      return MLDSA65_OID;
    case YKPIV_ALGO_MLDSA87:
      return MLDSA87_OID;
    case YKPIV_ALGO_MLKEM512:
      return MLKEM512_OID;
    case YKPIV_ALGO_MLKEM768:
      return MLKEM768_OID;
    case YKPIV_ALGO_MLKEM1024:
      return MLKEM1024_OID;
    default:
      if (oid_len != NULL) {
        *oid_len = 0;
      }
      return NULL;
  }
}

size_t pqc_get_public_key_size(unsigned char algorithm) {
  switch (algorithm) {
    // ML-DSA public key sizes (from FIPS 204)
    case YKPIV_ALGO_MLDSA44:
      return 1312;
    case YKPIV_ALGO_MLDSA65:
      return 1952;
    case YKPIV_ALGO_MLDSA87:
      return 2592;

    // ML-KEM public key sizes (from FIPS 203)
    case YKPIV_ALGO_MLKEM512:
      return 800;
    case YKPIV_ALGO_MLKEM768:
      return 1184;
    case YKPIV_ALGO_MLKEM1024:
      return 1568;

    default:
      return 0;
  }
}

unsigned char pqc_detect_algorithm_by_size(size_t pubkey_len) {
  switch (pubkey_len) {
    // ML-DSA variants
    case 1312:
      return YKPIV_ALGO_MLDSA44;
    case 1952:
      return YKPIV_ALGO_MLDSA65;
    case 2592:
      return YKPIV_ALGO_MLDSA87;

    // ML-KEM variants
    case 800:
      return YKPIV_ALGO_MLKEM512;
    case 1184:
      return YKPIV_ALGO_MLKEM768;
    case 1568:
      return YKPIV_ALGO_MLKEM1024;

    default:
      return 0;  // Not a recognized PQC key size
  }
}

CK_KEY_TYPE pqc_get_key_type(unsigned char algorithm) {
  if (YKPIV_IS_MLDSA(algorithm)) {
    return CKK_ML_DSA;
  }
  if (YKPIV_IS_MLKEM(algorithm)) {
    return CKK_ML_KEM;
  }
  return CK_UNAVAILABLE_INFORMATION;
}
