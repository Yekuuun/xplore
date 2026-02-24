#include "ftrace_helper.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

/**
 * Ftrace needs to know the address of the original function that we
 * are going to hook. As before, we just use kallsyms_lookup_name() 
 * to find the address in kernel memory.
 */
static int fh_resolve_hook_address(pftrace_hook hook) {
#ifdef KPROBE_LOOKUP

    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    int err;
    
    err = register_kprobe(&kp);
    if (err) {
        pr_err("[!] register_kprobe failed: %d\n", err);
        return err;
    }

    if (!kp.addr) {
        pr_err("[!] kallsyms_lookup_name not resolved\n");
        unregister_kprobe(&kp);
        return -ENOENT;
    }

    kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

#endif
    
    hook->address = kallsyms_lookup_name(hook->name);
    if(!hook->address){
        pr_err("[!] kallsyms_lookup_name not resolved\n");
        return -ENOENT;
    }


/**
 * Resolves the address of the original function to be hooked.
 *
 * Depending on the kernel configuration, we need to skip the __fentry__
 * instruction inserted by the compiler at the beginning of each traceable
 * function. On architectures where USE_FENTRY_OFFSET is set, we skip
 * MCOUNT_INSN_SIZE bytes to point past the __fentry__ call and directly
 * to the real function body, preventing an infinite loop when the original
 * function is called from the hook.
 *
 * @param hook: pointer to the ftrace_hook structure to resolve
*/
#if USE_FENTRY_OFFSET
    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else 
    *((unsigned long*) hook->original) = hook->address;
#endif

    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs) {
    pftrace_hook hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
    regs->ip = (unsigned long) hook->function;
#else
    if(!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->function;
#endif
}

/**
 * Assuming we've already set hook->name, hook->function and hook->original, we 
 * can go ahead and install the hook with ftrace. This is done by setting the 
 * ops field of hook (see the comment below for more details), and then using
 * the built-in ftrace_set_filter_ip() and register_ftrace_function() functions
 * provided by ftrace.h
 */
int fh_install_hook(pftrace_hook hook) {
    int err;

    err = fh_resolve_hook_address(hook);
    if(err)
        return err;

    /*
     * For many of function hooks (especially non-trivial ones), the $rip
     * register gets modified, so we have to alert ftrace to this fact. This
     * is the reason for the SAVE_REGS and IP_MODIFY flags. However, we also
     * need to OR the RECURSION_SAFE flag (effectively turning if OFF) because
     * the built-in anti-recursion guard provided by ftrace is useless if
     * we're modifying $rip. This is why we have to implement our own checks
     * (see USE_FENTRY_OFFSET). 
     */
    hook->ops.func = fh_ftrace_thunk;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;
#else
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE | FTRACE_OPS_FL_IPMODIFY;
#endif

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if(err){
        pr_err("[!] Error calling ftrace_set_filter_ip() with code : %d \n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if(err){
        pr_err("[!] Error calling ftrace_set_filter_ip() with code : %d \n", err);
        return err;
    }

    return 0;
}

/**
 * Disabling our function hook is just a simple matter of calling the built-in
 * unregister_ftrace_function() and ftrace_set_filter_ip() functions (note the
 * opposite order to that in fh_install_hook()).
 */
void fh_remove_hook(pftrace_hook hook){
    // to do.
}