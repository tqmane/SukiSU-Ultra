#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/task_work.h>
#include <linux/errno.h>
#include <linux/fdtable.h>

/* ---- strncpy_from_user_nofault compat (defined in kernel_compat.c) ---- */
extern long ksu_strncpy_from_user_nofault(char *dst,
                                          const void __user *unsafe_addr,
                                          long count);

/* ---- filp_open / kernel_read / kernel_write compat ---- */
extern struct file *ksu_filp_open_compat(const char *filename, int flags,
                                         umode_t mode);
extern ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
                                      loff_t *pos);
extern ssize_t ksu_kernel_write_compat(struct file *p, const void *buf,
                                       size_t count, loff_t *pos);

/* ---- copy_from_user_nofault for < 5.8 ---- */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
static inline long copy_from_user_nofault(void *to, const void __user *from,
                                          unsigned long n)
{
        return copy_from_user(to, from, n) ? -EFAULT : 0;
}

static inline long copy_to_user_nofault(void __user *to, const void *from,
                                        unsigned long n)
{
        return copy_to_user(to, from, n) ? -EFAULT : 0;
}

/* Keep the old name for files that call it directly */
static inline long strncpy_from_user_nofault(char *dst,
                                             const char __user *src,
                                             long count)
{
        return strncpy_from_user(dst, src, count);
}
#endif

/* ---- ksu_copy_from_user_retry ---- */
static inline long ksu_copy_from_user_retry(void *to, const void __user *from,
                                            unsigned long count)
{
    long ret = copy_from_user_nofault(to, from, count);
    if (likely(!ret))
        return ret;
    return copy_from_user(to, from, count);
}

/* ---- access_ok compat ---- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define ksu_access_ok(addr, size) access_ok(addr, size)
#else
#define ksu_access_ok(addr, size) access_ok(VERIFY_READ, addr, size)
#endif

/* ---- force_sig compat ---- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
#define __force_sig(sig) force_sig(sig)
#else
#define __force_sig(sig) force_sig(sig, current)
#endif

/* ---- TWA_RESUME compat ---- */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#ifndef TWA_RESUME
#define TWA_RESUME true
#endif
#endif

/* ---- do_close_fd compat ---- */
static inline int do_close_fd(unsigned int fd)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    return close_fd(fd);
#else
    return __close_fd(current->files, fd);
#endif
}

/* ---- seccomp filter_count compat ---- */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
#define KSU_NO_SECCOMP_FILTER_COUNT
#endif

/* ---- path_mount compat for < 5.9 (defined in kernel_compat.c) ---- */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
extern int ksu_path_mount(const char *dev_name, struct path *path,
                          const char *type_page, unsigned long flags,
                          void *data_page);
#define path_mount ksu_path_mount
#endif

/* ---- kvrealloc compat ---- */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
extern void *ksu_compat_kvrealloc(const void *p, size_t oldsize, size_t newsize,
                                  gfp_t flags);
#endif

#endif
