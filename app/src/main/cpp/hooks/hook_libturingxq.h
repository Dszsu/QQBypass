#ifndef NATIVE_BYPASS_HOOK_LIBTURINGXQ_H
#define NATIVE_BYPASS_HOOK_LIBTURINGXQ_H

#include "hook_libc.h"

namespace hook_libturingxq {

/**
 * Hook libturingxq.so (Tencent TuringFD security SDK)
 * - ART method integrity checks
 * - Risk detection and reporting
 */
void install_hooks();
void install_hooks_for_lib(const char* target_lib);
void patch_libturingxq_in_memory();

} // namespace hook_libturingxq

#endif // NATIVE_BYPASS_HOOK_LIBTURINGXQ_H
