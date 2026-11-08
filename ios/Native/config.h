/* libfko client-only configuration for Darwin. Shared vendored source, no JNI. */
#ifndef SPA_IOS_CONFIG_H
#define SPA_IOS_CONFIG_H
#include "../../android/app/src/main/cpp/config.h"
/* Darwin has no Linux endian.h. sys/types.h defines BYTE_ORDER. */
#undef HAVE_ENDIAN_H
#define SPA_USE_ARC4RANDOM 1
#ifdef __APPLE__
#define HAVE_STRLCPY 1
#define HAVE_STRLCAT 1
#endif
#endif
