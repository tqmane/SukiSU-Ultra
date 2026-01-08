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
#include <linux/sched/user.h>
#include <linux/uidgid.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#endif

#include "allowlist.h"
#include "setuid_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "manager.h"
#include "selinux/selinux.h"
#include "seccomp_cache.h"
#include "supercalls.h"
#include "syscall_hook_manager.h"
#include "kernel_umount.h"
#include "kernel_compat.h"

static void ksu_install_manager_fd_tw_func(struct callback_head *cb)
{
    ksu_install_fd();
    kfree(cb);
}

int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    uid_t new_uid = ruid;
    uid_t old_uid = current_uid().val;

    pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    /*
     * Zygote (and freshly forked children before selinux context switch) will
     * still match is_zygote() here. Mark it so SUS_MOUNT mount-id reordering
     * stays effective after the context changes.
     */
    if (is_zygote(current_cred()) &&
        !(current->susfs_task_state & TASK_STRUCT_IS_ZYGOTE)) {
        current->susfs_task_state |= TASK_STRUCT_IS_ZYGOTE;
    }
/*
    if (is_zygote(current_cred()) &&
        !(current->android_kabi_reserved1 & TASK_STRUCT_KABI1_IS_ZYGOTE)) {
        current->android_kabi_reserved1 |= TASK_STRUCT_KABI1_IS_ZYGOTE;
    }
*/
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
    /*
     * SUS_PATH hiding is keyed off current_cred()->user->android_kabi_reserved1.
     * This hook runs at syscall-enter, so current_cred()->user is still the old
     * uid. Use find_user(new_uid) to tag the target uid's user_struct.
     */
    if (is_appuid(new_uid) && new_uid > 2000 && !ksu_is_allow_uid(new_uid)) {
        kuid_t kuid = make_kuid(current_user_ns(), new_uid);
        if (uid_valid(kuid)) {
            struct user_struct *user = find_user(kuid);
            if (user) {
                user->android_kabi_reserved1 |=
                    USER_STRUCT_KABI1_NON_ROOT_USER_APP_PROFILE;
                free_uid(user);
            }
			current->susfs_task_state |= TASK_STRUCT_NON_ROOT_USER_APP_PROC;
        }
    }
#endif

    if (likely(ksu_is_manager_appid_valid()) &&
        unlikely(ksu_get_manager_appid() == new_uid % PER_USER_RANGE)) {
        spin_lock_irq(&current->sighand->siglock);
        ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        ksu_set_task_tracepoint_flag(current);
        spin_unlock_irq(&current->sighand->siglock);

        pr_info("install fd for manager: %d\n", new_uid);
        struct callback_head *cb = kzalloc(sizeof(*cb), GFP_ATOMIC);
        if (!cb)
            return 0;
        cb->func = ksu_install_manager_fd_tw_func;
        if (task_work_add(current, cb, TWA_RESUME)) {
            kfree(cb);
            pr_warn("install manager fd add task_work failed\n");
        }
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

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
    if ((is_appuid(new_uid) || is_isolated_process(new_uid)) &&
        ksu_uid_should_umount(new_uid)) {
        susfs_try_umount(new_uid);
    }
#endif

    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

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
