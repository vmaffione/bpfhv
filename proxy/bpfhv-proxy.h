#ifndef __BPFHV_PROXY_H__
#define __BPFHV_PROXY_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum BpfhvProxyReqType {
    BPFHV_PROXY_REQ_NONE = 0,
    BPFHV_PROXY_REQ_GET_FEATURES,
    BPFHV_PROXY_REQ_SET_FEATURES,
} BpfhvProxyReqType;

typedef struct BpfhvProxyMessage {
    BpfhvProxyReqType   reqtype;
    uint32_t            flags;
    uint32_t            size;
    union {
        uint64_t    u64;
    } payload;
} __attribute__((packed)) BpfhvProxyMessage;

#ifdef __cplusplus
}
#endif

#endif  /* __BPFHV_PROXY_H__ */
