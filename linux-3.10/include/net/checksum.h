/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Checksumming functions for IP, TCP, UDP and so on
 *
 * Authors:	Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Borrows very liberally from tcp.c and ip.c, see those
 *		files for more names.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

/* checksum的原理非常简单：
 * 将所有的内容以16-bits为单位进行相加
 * 最终的结果就是checksum值
 *
 * 校验和是16位字补码和，数据块长度为奇数时，数据块末尾填零处理 !
 *
 * TCP校验和覆盖TCP首部和TCP数据
 * 而IP首部中的校验和只覆盖IP的首部，不覆盖IP数据报中的任何数据
 * TCP的校验和是必须的，而UDP的校验和是可选的
 * TCP和UDP计算校验和时，都要加上一个12字节的伪首部
 *
 * TCP checksum的定义：
 *  1. 将伪头部、TCP报头、TCP数据分为16位的字，如果总长度为奇数个字节，则在最后添加一个全0的字节。
 *  2. 把TCP报头中的校验和字段置为0
 *  3. 用反码相加法累加所有16位字，（进位也要累加）
 *  4. 对计算结果取反，作为TCP的校验和
 */

#ifndef _CHECKSUM_H
#define _CHECKSUM_H

#include <linux/errno.h>
#include <asm/types.h>
#include <asm/byteorder.h>
#include <asm/uaccess.h>
#include <asm/checksum.h>

#ifndef _HAVE_ARCH_COPY_AND_CSUM_FROM_USER
/* 将数据从user space拷贝到kernel space, 并且同时计算它的部分累加和 */
static inline
__wsum csum_and_copy_from_user (const void __user *src, void *dst,
				      int len, __wsum sum, int *err_ptr)
{
	if (access_ok(VERIFY_READ, src, len))
		return csum_partial_copy_from_user(src, dst, len, sum, err_ptr);

	if (len)
		*err_ptr = -EFAULT;

	return sum;
}
#endif

#ifndef HAVE_CSUM_COPY_USER
static __inline__ __wsum csum_and_copy_to_user
(const void *src, void __user *dst, int len, __wsum sum, int *err_ptr)
{
	sum = csum_partial(src, len, sum);

	if (access_ok(VERIFY_WRITE, dst, len)) {
		if (copy_to_user(dst, src, len) == 0)
			return sum;
	}
	if (len)
		*err_ptr = -EFAULT;

	return (__force __wsum)-1; /* invalid checksum */
}
#endif

/* checksum 相加，应用场景：ip fragment合并时要更新checksum 
 * TODO：不是直接相加就好了吗？ 为什么需要(res < (__force u32)addend) ? */
static inline __wsum csum_add(__wsum csum, __wsum addend)
{
	u32 res = (__force u32)csum;
	res += (__force u32)addend;
	return (__force __wsum)(res + (res < (__force u32)addend));
}

static inline __wsum csum_sub(__wsum csum, __wsum addend)
{
	return csum_add(csum, ~addend);
}

static inline __wsum
csum_block_add(__wsum csum, __wsum csum2, int offset)
{
	u32 sum = (__force u32)csum2;
    /* TODO: 如果csum字段的长度是奇数，为什么对cum2进行如下变换 */
	if (offset&1)
		sum = ((sum&0xFF00FF)<<8)+((sum>>8)&0xFF00FF);
	return csum_add(csum, (__force __wsum)sum);
}

static inline __wsum
csum_block_sub(__wsum csum, __wsum csum2, int offset)
{
	u32 sum = (__force u32)csum2;
	if (offset&1)
		sum = ((sum&0xFF00FF)<<8)+((sum>>8)&0xFF00FF);
	return csum_sub(csum, (__force __wsum)sum);
}

static inline __wsum csum_unfold(__sum16 n)
{
	return (__force __wsum)n;
}

#define CSUM_MANGLED_0 ((__force __sum16)0xffff)

static inline void csum_replace4(__sum16 *sum, __be32 from, __be32 to)
{
	__be32 diff[] = { ~from, to };

	*sum = csum_fold(csum_partial(diff, sizeof(diff), ~csum_unfold(*sum)));
}

static inline void csum_replace2(__sum16 *sum, __be16 from, __be16 to)
{
	csum_replace4(sum, (__force __be32)from, (__force __be32)to);
}

struct sk_buff;
extern void inet_proto_csum_replace4(__sum16 *sum, struct sk_buff *skb,
				     __be32 from, __be32 to, int pseudohdr);
extern void inet_proto_csum_replace16(__sum16 *sum, struct sk_buff *skb,
				      const __be32 *from, const __be32 *to,
				      int pseudohdr);

static inline void inet_proto_csum_replace2(__sum16 *sum, struct sk_buff *skb,
					    __be16 from, __be16 to,
					    int pseudohdr)
{
	inet_proto_csum_replace4(sum, skb, (__force __be32)from,
				 (__force __be32)to, pseudohdr);
}

#endif
