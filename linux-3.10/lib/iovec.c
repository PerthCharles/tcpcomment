#include <linux/uaccess.h>
#include <linux/export.h>
#include <linux/uio.h>

/*
 *	Copy iovec to kernel. Returns -EFAULT on error.
 *
 *	Note: this modifies the original iovec.
 */

int memcpy_fromiovec(unsigned char *kdata, struct iovec *iov, int len)
{
	while (len > 0) {
		if (iov->iov_len) {
			int copy = min_t(unsigned int, len, iov->iov_len);
			if (copy_from_user(kdata, iov->iov_base, copy))
				return -EFAULT;
			len -= copy;
			kdata += copy;
			iov->iov_base += copy;
			iov->iov_len -= copy;
		}
		iov++;
	}

	return 0;
}
EXPORT_SYMBOL(memcpy_fromiovec);

/*
 *	Copy kernel to iovec. Returns -EFAULT on error.
 *
 *	Note: this modifies the original iovec.
 */
/* 拷贝数据到iovec */
/* TODO: 突然想到一个脑洞: 用户调用时那个buffer仅仅是一个指针而已。如果在调用的时候将它设计成符合iovec结构体的buffer，
 * 会不会使recv()可以同时用多个不连续的buffer block接收数据呢? */
int memcpy_toiovec(struct iovec *iov, unsigned char *kdata, int len)
{
	while (len > 0) {
		if (iov->iov_len) {
			int copy = min_t(unsigned int, iov->iov_len, len);
			if (copy_to_user(iov->iov_base, kdata, copy))
				return -EFAULT;
			kdata += copy;
			len -= copy;
			iov->iov_len -= copy;
			iov->iov_base += copy;
		}
        /* iovec可能有多个buffer */
		iov++;
	}

	return 0;
}
EXPORT_SYMBOL(memcpy_toiovec);
