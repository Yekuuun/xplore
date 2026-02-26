#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/init.h>
#include "../lib/hook/ftrace_helper.h"

#define MODNAME "hook_lkm"

MODULE_AUTHOR("Yekuuun");
MODULE_DESCRIPTION("Simple function hooking demo");
MODULE_LICENSE("GPL");

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_mkdir)(const struct pt_regs *regs);

static asmlinkage long hook_mkdir(const struct pt_regs *regs) {
    char __user *pathname = (char *)regs->di;
    char path[NAME_MAX] = { 0 };

    if (strncpy_from_user(path, pathname, NAME_MAX) > 0)
        pr_info("[ftrace_test] mkdir called: %s\n", path);

    return orig_mkdir(regs);
}
#else
static asmlinkage long (*orig_mkdir)(const char __user *pathname, umode_t mode);

static asmlinkage long hook_mkdir(const char __user *pathname, umode_t mode) {
    char path[NAME_MAX] = { 0 };

    if (strncpy_from_user(path, pathname, NAME_MAX) > 0)
        pr_info("[ftrace_test] mkdir called: %s\n", path);

    return orig_mkdir(pathname, mode);
}
#endif

/* Déclaration du tableau de hooks */
static ftrace_hook hooks[] = {
    HOOK("__x64_sys_mkdir", hook_mkdir, &orig_mkdir),
};

static int __init test_module_init(void) {
    int err;

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        pr_err("[ftrace_test] Failed to install hooks: %d\n", err);
        return err;
    }

    pr_info("[ftrace_test] Module loaded, hooks installed.\n");
    return 0;
}

static void __exit test_module_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    pr_info("[ftrace_test] Module unloaded, hooks removed.\n");
}

module_init(test_module_init);
module_exit(test_module_exit);