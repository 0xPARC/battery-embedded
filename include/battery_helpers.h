#ifndef BATTERY_HELPERS_H
#define BATTERY_HELPERS_H

#include <stdint.h>
#include <stddef.h>
#include "battery.h"

// Map BATTERY status codes to strings for logging
static inline const char* battery_strerror(int code) {
    switch (code) {
        case BATTERY_OK: return "BATTERY_OK";
        case BATTERY_ERR_NULL: return "BATTERY_ERR_NULL";
        case BATTERY_ERR_BADLEN: return "BATTERY_ERR_BADLEN";
        case BATTERY_ERR_SEEDLEN: return "BATTERY_ERR_SEEDLEN";
        case BATTERY_ERR_INPUT: return "BATTERY_ERR_INPUT";
        case BATTERY_ERR_BUFSZ: return "BATTERY_ERR_BUFSZ";
        default: return "BATTERY_ERR_UNKNOWN";
    }
}

// No explicit alignment checks are needed; all FFI I/O uses opaque byte buffers.

#endif // BATTERY_HELPERS_H
