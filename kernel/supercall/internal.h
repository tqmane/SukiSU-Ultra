#ifndef __KSU_H_SUPERCALL_INTERNAL
#define __KSU_H_SUPERCALL_INTERNAL

#include <linux/types.h>
#include <linux/uaccess.h>

bool only_manager(void);
bool only_root(void);
bool manager_or_root(void);
bool always_allow(void);
bool allowed_for_su(void);

long ksu_supercall_handle_ioctl(unsigned int cmd, void __user *argp);
void ksu_supercall_dump_commands(void);
void ksu_supercall_cleanup_state(void);
#ifdef CONFIG_KSU_SUSFS
int ksu_handle_susfs_reboot_cmd(unsigned int cmd, void __user **arg);
#endif

#endif // __KSU_H_SUPERCALL_INTERNAL
