#include <linux/version.h>
#include <linux/fs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task.h>
#else
#include <linux/sched.h>
#endif
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"

struct file *ksu_filp_open_compat(const char *filename, int flags, umode_t mode)
{
    return filp_open(filename, flags, mode);
}

ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
                               loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    return kernel_read(p, buf, count, pos);
#else
    loff_t offset = pos ? *pos : 0;
    ssize_t result = kernel_read(p, offset, (char *)buf, count);
    if (pos && result > 0) {
        *pos = offset + result;
    }
    return result;
#endif
}

ssize_t ksu_kernel_write_compat(struct file *p, const void *buf, size_t count,
                                loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    return kernel_write(p, buf, count, pos);
#else
    loff_t offset = pos ? *pos : 0;
    ssize_t result = kernel_write(p, buf, count, offset);
    if (pos && result > 0) {
        *pos = offset + result;
    }
    return result;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
                                   long count)
{
    return strncpy_from_user_nofault(dst, unsafe_addr, count);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
                                   long count)
{
    return strncpy_from_unsafe_user(dst, unsafe_addr, count);
}
#else
long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
                                   long count)
{
    mm_segment_t old_fs = get_fs();
    long ret;

    if (unlikely(count <= 0))
        return 0;

    set_fs(USER_DS);
    pagefault_disable();
    ret = strncpy_from_user(dst, unsafe_addr, count);
    pagefault_enable();
    set_fs(old_fs);

    if (ret >= count) {
        ret = count;
        dst[ret - 1] = '\0';
    } else if (ret > 0) {
        ret++;
    }

    return ret;
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0))
int ksu_path_mount(const char *dev_name, struct path *path,
                   const char *type_page, unsigned long flags,
                   void *data_page)
{
    char buf[384] = { 0 };
    mm_segment_t old_fs;
    long ret;
    char *realpath = d_path(path, buf, sizeof(buf) - 1);

    if (IS_ERR(realpath))
        return PTR_ERR(realpath);

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = do_mount(dev_name, (const char __user *)realpath, type_page, flags,
                   data_page);
    set_fs(old_fs);
    return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
static void *__ksu_kvmalloc(size_t size, gfp_t flags)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
    void *buffer = NULL;

    if (size == 0)
        return NULL;

    if (size <= (16 * PAGE_SIZE))
        buffer = kmalloc(size, flags | GFP_NOIO | __GFP_NOWARN);
    if (!buffer) {
        if (flags & __GFP_ZERO)
            buffer = vzalloc(size);
        else
            buffer = vmalloc(size);
    }
    return buffer;
#else
    return kvmalloc(size, flags);
#endif
}

void *ksu_compat_kvrealloc(const void *p, size_t oldsize, size_t newsize,
                           gfp_t flags)
{
    void *newp;

    if (oldsize >= newsize)
        return (void *)p;
    newp = __ksu_kvmalloc(newsize, flags);
    if (!newp)
        return NULL;
    memcpy(newp, p, oldsize);
    kvfree(p);
    return newp;
}
#endif
