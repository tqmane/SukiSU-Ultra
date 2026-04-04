#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#include <linux/susfs_def.h>
#endif

#include "allowlist.h"
#include "setuid_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "manager.h"
#include "selinux/selinux.h"
#include "seccomp_cache.h"
#include "supercalls.h"
#include "syscall_hook_manager.h"
#include "kernel_umount.h"
#include "kernel_compat.h"

extern void disable_seccomp(void);

#ifdef CONFIG_KSU_SUSFS
struct susfs_handle_setuid_tw {
    struct callback_head cb;
};

static void susfs_handle_setuid_tw_func(struct callback_head *cb)
{
    struct susfs_handle_setuid_tw *tw =
        container_of(cb, struct susfs_handle_setuid_tw, cb);
    const struct cred *saved;

    if (!ksu_cred) {
        kfree(tw);
        return;
    }

    saved = override_creds(ksu_cred);
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
    susfs_run_sus_path_loop(current_uid().val);
#endif
    revert_creds(saved);
    kfree(tw);
}

static void ksu_handle_extra_susfs_work(uid_t new_uid)
{
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
    struct susfs_handle_setuid_tw *tw;

    if (!is_appuid(new_uid) && !is_isolated_process(new_uid))
        return;

    tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
    if (!tw) {
        pr_err("susfs: failed to allocate task_work\n");
        return;
    }

    tw->cb.func = susfs_handle_setuid_tw_func;
    if (task_work_add(current, &tw->cb, TWA_RESUME)) {
        kfree(tw);
        pr_err("susfs: failed adding task_work\n");
    }
#endif

    if (is_appuid(new_uid) || is_isolated_process(new_uid))
        susfs_set_current_proc_umounted();
}
#endif

int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    uid_t new_uid = ruid;
    uid_t old_uid = current_uid().val;

    pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    if (likely(ksu_is_manager_appid_valid()) &&
        unlikely(ksu_get_manager_appid() == new_uid % PER_USER_RANGE)) {
        spin_lock_irq(&current->sighand->siglock);
        ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        ksu_set_task_tracepoint_flag(current);
        spin_unlock_irq(&current->sighand->siglock);

        pr_info("install fd for manager: %d\n", new_uid);
        ksu_install_fd();
        return 0;
    }

    if (ksu_is_allow_uid_for_current(new_uid)) {
        if (current->seccomp.mode == SECCOMP_MODE_FILTER &&
            current->seccomp.filter) {
            spin_lock_irq(&current->sighand->siglock);
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
            spin_unlock_irq(&current->sighand->siglock);
        }
        ksu_set_task_tracepoint_flag(current);
    } else {
        ksu_clear_task_tracepoint_flag_if_needed(current);
    }
#else /* LINUX_VERSION_CODE < 5.10.0 */
    // Fix: Manager fd installation must NOT be gated behind the allowlist
    // check. On fresh install, the manager is not in the allowlist yet, so
    // seccomp would never be disabled and the fd would never be installed.
    // This mirrors the 5.10+ path which separates manager and allowlist checks.
    if (ksu_is_manager_appid_valid() &&
        ksu_get_manager_appid() == new_uid % PER_USER_RANGE) {
        disable_seccomp();
        pr_info("install fd for ksu manager(uid=%d)\n", new_uid);
        ksu_install_fd();
        return 0;
    }

    if (ksu_is_allow_uid_for_current(new_uid)) {
        disable_seccomp();
        return 0;
    }
#endif

    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

#ifdef CONFIG_KSU_SUSFS
    if (ksu_is_manager_appid_valid() && is_zygote(get_current_cred()) &&
        (is_appuid(new_uid) || is_isolated_process(new_uid)) &&
        (ksu_uid_should_umount(new_uid) || is_isolated_process(new_uid))) {
        ksu_handle_extra_susfs_work(new_uid);
    }
#endif

    return 0;
}

void ksu_setuid_hook_init(void)
{
    ksu_kernel_umount_init();
}

void ksu_setuid_hook_exit(void)
{
    pr_info("ksu_core_exit\n");
    ksu_kernel_umount_exit();
}
