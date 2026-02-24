/**
 * Helper file for ftrace hooking kernel functions.
 * 
 * Sources : 
 * https://github.com/xcellerator/linux_kernel_hacking/blob/master/3_RootkitTechniques/3.9_hiding_logged_in_users/ftrace_helper.h
 * https://github.com/proxytype/kprobes-hooks/
 * https://github.com/xcellerator/linux_kernel_hacking/blob/master/3_RootkitTechniques/3.9_hiding_logged_in_users/ftrace_helper.h
 * 
 * @author Yekuuun
 */

#ifndef  FTRACE_HELPER_H
#define  FTRACE_HELPER_H

#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#include <linux/kprobes.h>
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/**
 * We pack all the information we need (name, hooking function, original function)
 * into this struct. This makes is easier for setting up the hook and just passing
 * the entire struct off to fh_install_hook() later on.
 */
typedef struct ftrace_hook {
    const char *name;
    void (*function)(void);
    void (*original)(void);

    unsigned long address;
    struct ftrace_ops ops;
} ftrace_hook, *pftrace_hook;

/**
 * Utility function for settings ops attributes
 */
#define HOOK(_name, _hook, _orig) \
{                                 \
    .name     = (_name),          \
    .function = (_hook),          \
    .original = (_orig),          \
}                                 \

/**
 * We need to prevent recursive loops when hooking, otherwise the kernel will
 * panic and hang. The options are to either detect recursion by looking at
 * the function return address, or by jumping over the ftrace call. We use the 
 * first option, by setting USE_FENTRY_OFFSET = 0, but could use the other by
 * setting it to 1. (Oridinarily ftrace provides it's own protections against
 * recursion, but it relies on saving return registers in $rip. We will likely
 * need the use of the $rip register in our hook, so we have to disable this
 * protection and implement our own).
 * 
*/
#define USE_FENTRY_OFFSET 0
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

/**
 * Idea from RtlSecureZeroMemory
 * securely fills a block of memory with zeros in a way that is guaranteed not to be optimized away by the compiler.
 */
static inline void secure_zero_memory(void *s, size_t n)
{
    memset(s, 0, n);
    barrier_data(s);
}

#endif