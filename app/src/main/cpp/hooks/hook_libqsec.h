#ifndef HOOK_LIBQSEC_H
#define HOOK_LIBQSEC_H

namespace hook_libqsec {

/**
 * Install hooks for libQSec.so
 *
 * Blocks anti-hook detection mechanisms:
 * - dlopen/dlsym/dladdr scanning for hook frameworks
 * - sigaction timer-based self-checks (future)
 */
void install_qsec_hooks();
void patch_libqsec_in_memory();

} // namespace hook_libqsec

using hook_libqsec::install_qsec_hooks;
using hook_libqsec::patch_libqsec_in_memory;

#endif // HOOK_LIBQSEC_H
