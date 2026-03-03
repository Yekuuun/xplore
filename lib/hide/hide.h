/**
 * Base lib for the hide_lkm module.
 * Contains utility functions for playing with intern module list.
 * 
 * @author Yekuuun
 */

#ifndef HIDE_H
#define HIDE_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>

void hideme(struct list_head *node);
void showme(struct list_head *prev);

#endif