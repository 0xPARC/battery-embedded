#ifndef BATTERY_HELPERS_H
#define BATTERY_HELPERS_H

#include <stdint.h>
#include <stddef.h>
#include "battery.h"

// Map BATTERY status codes to strings for logging
static inline const char* battery_strerror(int code) {
    switch (code) {
        case TFHE_OK: return "TFHE_OK";
        case TFHE_ERR_NULL: return "TFHE_ERR_NULL";
        case TFHE_ERR_BADLEN: return "TFHE_ERR_BADLEN";
        case TFHE_ERR_SEEDLEN: return "TFHE_ERR_SEEDLEN";
        case TFHE_ERR_ZKP_INPUT: return "TFHE_ERR_ZKP_INPUT";
        case TFHE_ERR_ZKP_BUFSZ: return "TFHE_ERR_ZKP_BUFSZ";
        default: return "TFHE_ERR_UNKNOWN";
    }
}

// No explicit alignment checks are needed; all FFI I/O uses opaque byte buffers.

#endif // BATTERY_HELPERS_H
