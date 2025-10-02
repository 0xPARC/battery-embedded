#ifndef TFHE_ENC_HELPERS_H
#define TFHE_ENC_HELPERS_H

#include <stdint.h>
#include <stddef.h>
#include "tfhe_enc.h"

// Map TFHE status codes to strings for logging
static inline const char* tfhe_strerror(int code) {
    switch (code) {
        case TFHE_OK: return "TFHE_OK";
        case TFHE_ERR_NULL: return "TFHE_ERR_NULL";
        case TFHE_ERR_BADLEN: return "TFHE_ERR_BADLEN";
        case TFHE_ERR_ALIGN: return "TFHE_ERR_ALIGN";
        case TFHE_ERR_SEEDLEN: return "TFHE_ERR_SEEDLEN";
        case TFHE_ERR_ZKP_INPUT: return "TFHE_ERR_ZKP_INPUT";
        case TFHE_ERR_ZKP_BUFSZ: return "TFHE_ERR_ZKP_BUFSZ";
        default: return "TFHE_ERR_UNKNOWN";
    }
}

// Check 8-byte alignment for u64 arrays
static inline int tfhe_is_aligned_u64(const void* p) {
    return (((uintptr_t)p) & (sizeof(uint64_t) - 1)) == 0;
}

#endif // TFHE_ENC_HELPERS_H
