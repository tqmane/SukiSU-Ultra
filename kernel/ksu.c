#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/version.h>

#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "throne_tracker.h"
#include "syscall_hook_manager.h"
#include "ksud.h"
#include "supercalls.h"
#include "ksu.h"
#include "file_wrapper.h"
#include "app_profile.h"
#include "objsec.h"
#include "selinux/selinux.h"

struct cred *ksu_cred;

void sukisu_custom_config_init(void)
{
}

void sukisu_custom_config_exit(void)
{
}

int __init kernelsu_init(void)
{
#ifdef CONFIG_KSU_DEBUG
    pr_alert("*************************************************************");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("**                                                         **");
    pr_alert("**         You are running KernelSU in DEBUG mode          **");
    pr_alert("**                                                         **");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("*************************************************************");
#endif

    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
    }

    ksu_feature_init();

    ksu_supercalls_init();

    sukisu_custom_config_init();

    ksu_syscall_hook_manager_init();

    ksu_allowlist_init();

    ksu_throne_tracker_init();

    ksu_ksud_init();

    ksu_file_wrapper_init();

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
    kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
    return 0;
}

extern void ksu_observer_exit(void);
void kernelsu_exit(void)
{
    ksu_allowlist_exit();

    ksu_throne_tracker_exit();

    ksu_observer_exit();

    ksu_ksud_exit();

    ksu_syscall_hook_manager_exit();

    sukisu_custom_config_exit();

    ksu_supercalls_exit();

    ksu_feature_exit();

    if (ksu_cred) {
        put_cred(ksu_cred);
    }
}

module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);


// Susfs Sus SU support
static bool susfs_sus_su_enabled = false;

void ksu_susfs_enable_sus_su(void)
{
    susfs_sus_su_enabled = true;
}

void ksu_susfs_disable_sus_su(void)
{
    susfs_sus_su_enabled = false;
}

bool susfs_is_allow_su(void)
{
    return susfs_sus_su_enabled;
}

// Wrapper for susfs to check if current process is in KSU domain
bool susfs_is_current_ksu_domain(void)
{
    return is_ksu_domain();
}

void escape_to_root(void)
{
    escape_with_root_profile();
}

bool ksu_devpts_hook = true;
int ksu_handle_devpts(struct inode *inode)
{
    if (!susfs_is_allow_su()) {
        return 0;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) || defined(KSU_OPTIONAL_SELINUX_INODE)
    struct inode_security_struct *sec = selinux_inode(inode);
#else
    struct inode_security_struct *sec = (struct inode_security_struct *)inode->i_security;
#endif

    if (ksu_file_sid && sec) {
        sec->sid = ksu_file_sid;
    }
    return 0;
}
