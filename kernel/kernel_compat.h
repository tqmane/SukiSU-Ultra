#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>

/*
 * ksu_copy_from_user_retry
 * try nofault copy first, if it fails, try with plain
 * paramters are the same as copy_from_user
 * 0 = success
 */
static long ksu_copy_from_user_retry(void *to, const void __user *from,
                                     unsigned long count)
{
    long ret = copy_from_user_nofault(to, from, count);
    if (likely(!ret))
        return ret;

    // we faulted! fallback to slow path
    return copy_from_user(to, from, count);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
static inline long copy_from_user_nofault(void *to, const void __user *from,
					  unsigned long n)
{
	/*
	 * copy_from_user returns number of uncopied bytes; convert to
	 * 0/-EFAULT style used by newer nofault helper.
	 */
	return copy_from_user(to, from, n) ? -EFAULT : 0;
}

static inline long strncpy_from_user_nofault(char *dst,
					     const char __user *src,
					     long count)
{
	return strncpy_from_user(dst, src, count);
}
#endif

#endif
