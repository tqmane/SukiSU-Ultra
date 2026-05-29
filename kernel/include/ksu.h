#ifndef __KSU_H_KSU
#define __KSU_H_KSU

#include <linux/types.h>
#include <linux/cred.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#define KERNEL_SU_VERSION KSU_VERSION

extern struct cred *ksu_cred;
extern bool ksu_late_loaded;
extern bool allow_shell;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
struct selinux_policy;
extern struct selinux_policy *backup_sepolicy;
#else
struct selinux_ss;
extern struct selinux_ss *backup_sepolicy;
#endif
extern bool ksu_no_custom_rc;

// SukiSU Ultra kernel su version full strings
#ifndef KSU_VERSION_FULL
#define KSU_VERSION_FULL "v1.0-tqmane"
#endif

static inline int startswith(char *s, char *prefix)
{
    return strncmp(s, prefix, strlen(prefix));
}

static inline int endswith(const char *s, const char *t)
{
    size_t slen = strlen(s);
    size_t tlen = strlen(t);
    if (tlen > slen)
        return 1;
    return strcmp(s + slen - tlen, t);
}

#endif
