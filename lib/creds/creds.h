/**
 * This file contains function helper for the set_root module.
 * 
 * Sources : 
 * https://www.kernel.org/doc/html/v4.17/security/credentials.html
 * https://github.com/xcellerator/linux_kernel_hacking/blob/master/3_RootkitTechniques/3.3_set_root/rootkit.c
 * 
 * @author Yekuuun
 */

#ifndef  CREDS_H
#define  CREDS_h

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/cred.h>

int set_root(void);

#endif