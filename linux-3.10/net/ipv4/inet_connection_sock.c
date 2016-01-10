/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Support for INET connection oriented protocols.
 *
 * Authors:	See the TCP sources
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or(at your option) any later version.
 */

#include <linux/module.h>
#include <linux/jhash.h>

#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/inet_timewait_sock.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/tcp_states.h>
#include <net/xfrm.h>

#ifdef INET_CSK_DEBUG
const char inet_csk_timer_bug_msg[] = "inet_csk BUG: unknown timer value\n";
EXPORT_SYMBOL(inet_csk_timer_bug_msg);
#endif

/*
 * This struct holds the first and last local port number.
 */
/* 用于指定TCP和UDP在随机分配本地端口时的区间 */
struct local_ports sysctl_local_ports __read_mostly = {
	.lock = __SEQLOCK_UNLOCKED(sysctl_local_ports.lock),
    /* 端口会占用2字节，所以理论的最大值应该是65535 */
	.range = { 32768, 61000 },  
};

unsigned long *sysctl_local_reserved_ports;
EXPORT_SYMBOL(sysctl_local_reserved_ports);

/* 返回分配本地端口时，可供分配的区间 */
void inet_get_local_port_range(int *low, int *high)
{
	unsigned int seq;

	do {
		seq = read_seqbegin(&sysctl_local_ports.lock);

		*low = sysctl_local_ports.range[0];
		*high = sysctl_local_ports.range[1];
	} while (read_seqretry(&sysctl_local_ports.lock, seq));
}
EXPORT_SYMBOL(inet_get_local_port_range);

/* 该函数遍历这个tb->owners list, 判断以下条件是否成立
 *      sk2 = tb->owners
 *  a. sk与sk2绑定的网卡不一样，则sk与sk2之间可以共享port的，则继续检查下一个sk2; 否则继续检查条件b
 *  b. 如果sk和sk2都设置了reuse标记，并且sk2不是listen状态，那么sk与sk2可以共享port，继续检查下一个sk2；
 *  否则继续判断条件c
 *  c. 如果sk与sk2具体的rcv_saddr不一样，就说明sk与sk2可以共享port, 继续检查下一个sk2，否则跳出循环，就会导致sk2 != NULL
 */
int inet_csk_bind_conflict(const struct sock *sk,
			   const struct inet_bind_bucket *tb, bool relax)
{
	struct sock *sk2;
	int reuse = sk->sk_reuse;
	int reuseport = sk->sk_reuseport;
	kuid_t uid = sock_i_uid((struct sock *)sk);

	/*
	 * Unlike other sk lookup places we do not check
	 * for sk_net here, since _all_ the socks listed
	 * in tb->owners list belong to the same net - the
	 * one this bucket belongs to.
	 */

	sk_for_each_bound(sk2, &tb->owners) {
        /* 判断条件a */
		if (sk != sk2 &&
		    !inet_v6_ipv6only(sk2) &&
		    (!sk->sk_bound_dev_if ||
		     !sk2->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == sk2->sk_bound_dev_if)) {
            /* 判断条件b */
			if ((!reuse || !sk2->sk_reuse ||
			    sk2->sk_state == TCP_LISTEN) &&
			    (!reuseport || !sk2->sk_reuseport ||
			    (sk2->sk_state != TCP_TIME_WAIT &&
			     !uid_eq(uid, sock_i_uid(sk2))))) {
				const __be32 sk2_rcv_saddr = sk_rcv_saddr(sk2);
                /* 判断条件c */
				if (!sk2_rcv_saddr || !sk_rcv_saddr(sk) ||
				    sk2_rcv_saddr == sk_rcv_saddr(sk))
					break;
			}
			if (!relax && reuse && sk2->sk_reuse &&
			    sk2->sk_state != TCP_LISTEN) {
				const __be32 sk2_rcv_saddr = sk_rcv_saddr(sk2);

				if (!sk2_rcv_saddr || !sk_rcv_saddr(sk) ||
				    sk2_rcv_saddr == sk_rcv_saddr(sk))
					break;
			}
		}
	}
    /* 如果sk2等于NULL，则说明全部检查都pass了，可以bind reuse port，从而返回false, 表示不conflict */
	return sk2 != NULL;
}
EXPORT_SYMBOL_GPL(inet_csk_bind_conflict);

/* Obtain a reference to a local port for the given sock,
 * if snum is zero it means select any available local port.
 */
/* 分配端口 */
int inet_csk_get_port(struct sock *sk, unsigned short snum)
{
    /* 找到这个sk对应协议使用的hash结构体, tcp对应tcp_hashinfo */
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	struct inet_bind_hashbucket *head;
	struct inet_bind_bucket *tb;
	int ret, attempts = 5;
	struct net *net = sock_net(sk);
	int smallest_size = -1, smallest_rover;
	kuid_t uid = sock_i_uid(sk);

    /* 获取端口时，可能会改变hashinfo里面的内容(如分配 inet_bind_bucket)，因此需要关bottom half中断 */
	local_bh_disable();
    /* 如果snum为0，即没有指定具体需要绑定的端口，则'随机'分配一个没被使用的即可
     * 当然了，看完实现后就知道这个'随机'其实是很有规律的 */
	if (!snum) {
		int remaining, rover, low, high;

again:
        /* 获取分配端口的区间，默认是[32768, 61000] */
		inet_get_local_port_range(&low, &high);
		remaining = (high - low) + 1;       /* 总共有多少个port可供分配 */
        /* 返回一个随机值，给最开始的尝试分配的端口 
         * rover表示漫游，smallest_rover就是说从这个地方开始查找可用的port */
		smallest_rover = rover = net_random() % remaining + low;

		smallest_size = -1;
		do {
            /* 如果是系统预留的端口，则不能用于随机分配 */
			if (inet_is_reserved_local_port(rover))
				goto next_nolock;
            /* 找到rover端口对应的hash冲突链表的表头 */
			head = &hashinfo->bhash[inet_bhashfn(net, rover,
					hashinfo->bhash_size)];
            /* 锁住hash冲突链表 */
			spin_lock(&head->lock);
			inet_bind_bucket_for_each(tb, &head->chain)
                /* 如果找到了Rover端口对应的inet_bind_bucket结构体 */
				if (net_eq(ib_net(tb), net) && tb->port == rover) {
                    /* a. 如果设置了fastreuse标记，并且当前socket设置了port reuse标记，并且也不是listen状态，则跳到步骤c
                     *    否则跳到步骤b
                     * b. 如果设置了fastreuse标记，并且当前socket设置了port reuse标记，并且也不是listen状态，则跳到步骤c
                     *    否则跳到步骤d
                     * c. 如果该hash冲突链表是最小的一个，则跳转到步骤e,否则跳转到步骤d 
                     * d. 这个端口不能被reuse(重用)
                     * e. 端口能够被重用
                     * TODO: 以上就是基本的判断逻辑，至于bsockets、bind_conflict()就等后续再理解吧
                     */
					if ((   (tb->fastreuse > 0 && sk->sk_reuse && sk->sk_state != TCP_LISTEN) ||
					        (tb->fastreuseport > 0 && sk->sk_reuseport && uid_eq(tb->fastuid, uid))) 
                        &&
					    (tb->num_owners < smallest_size || smallest_size == -1)) {
						smallest_size = tb->num_owners;
						smallest_rover = rover;
						if (atomic_read(&hashinfo->bsockets) > (high - low) + 1 &&
						    !inet_csk(sk)->icsk_af_ops->bind_conflict(sk, tb, false)) {
							snum = smallest_rover;
							goto tb_found;
						}
					}
					if (!inet_csk(sk)->icsk_af_ops->bind_conflict(sk, tb, false)) {
						snum = rover;
						goto tb_found;
					}
					goto next;
				}
            /* break出去，则说明当前准备分配的端口没有被实际的任何socket占用，所以后面会进入tb_not_found逻辑 */
            /* 要理解这里，其实只要注意到inet_bind_bucket_for_each()循环没有加大括号就懂了 */
			break;      
		next:
			spin_unlock(&head->lock);
		next_nolock:
            /* 如果rover超过了high，则重新从low开始尝试。所以其实这个地方理论上能够遍历[low, high]的，
             * 只不过用个相对随机的rover来适当加速 */
			if (++rover > high)
				rover = low;
        /* 只要还有端口没有尝试，就可以继续尝试分配, 反正bind函数并不十分在意高性能 */
		} while (--remaining > 0);

		/* Exhausted local port range during search?  It is not
		 * possible for us to be holding one of the bind hash
		 * locks if this test triggers, because if 'remaining'
		 * drops to zero, we broke out of the do/while loop at
		 * the top level, not from the 'break;' statement.
		 */
		ret = 1;
        /* TODO：理解bsocket和bind_conflict()后再来具体解释smallest_size的作用吧 */
		if (remaining <= 0) {
			if (smallest_size != -1) {
				snum = smallest_rover;
				goto have_snum;
			}
            /* 如果找了个遍都没有找到，只好fail，返回1表示绑定port失败 */
			goto fail;
		}
		/* OK, here is the one we will use.  HEAD is
		 * non-NULL and we hold it's mutex.
		 */
		snum = rover;   /* 使用这个找到的端口 */
	} else {
        /* 如果指定了端口，则直接'尝试'绑定 */
have_snum:
        /* 拿到该端口对应的哈希冲突链表的表头 */
		head = &hashinfo->bhash[inet_bhashfn(net, snum,
				hashinfo->bhash_size)];
		spin_lock(&head->lock);
		inet_bind_bucket_for_each(tb, &head->chain)
            /* 如果net namespace和port号一致，则说明该端口已经被某个socket使用着，跳转到found处处理 */
			if (net_eq(ib_net(tb), net) && tb->port == snum)
				goto tb_found;
	}
    /* 什么情况会执行到这里？
     * a. 如果是没有指定snum的情况，则只能是上面的do...while()从break中跳出来了  ==> 端口未被使用，tb_not_found
     * b. 如果是指定了snum的情况，则说明没有找到port对应的bucket  ==> 端口未被使用，tb_not_found
     */
	tb = NULL;
    /* 如果端口之前没有被使用，则inet_bind_bucket就不会被找到，所以要跳转到not_found处处理 */
	goto tb_not_found;
tb_found:
    /* 如果inet_bind_bucket找到了，但是发现还能重用 */
	if (!hlist_empty(&tb->owners)) {
        /* 强制reuse */
		if (sk->sk_reuse == SK_FORCE_REUSE)
			goto success;

		if (((tb->fastreuse > 0 &&
		      sk->sk_reuse && sk->sk_state != TCP_LISTEN) ||
		     (tb->fastreuseport > 0 &&
		      sk->sk_reuseport && uid_eq(tb->fastuid, uid))) &&
		    smallest_size == -1) {
			goto success;
		} else {
			ret = 1;
            /* bind_conflict()执行具体的绑定动作, 对应tcp来说，是inet_csk_bind_conflict() */
			if (inet_csk(sk)->icsk_af_ops->bind_conflict(sk, tb, true)) {
				if (((sk->sk_reuse && sk->sk_state != TCP_LISTEN) ||
				     (tb->fastreuseport > 0 &&
				      sk->sk_reuseport && uid_eq(tb->fastuid, uid))) &&
				    smallest_size != -1 && --attempts >= 0) {
					spin_unlock(&head->lock);
					goto again;
				}

				goto fail_unlock;
			}
		}
	}
tb_not_found:
	ret = 1;
    /* 进入该路径，tb必须为NULL，不为空则出错返回
     * 同时创建一个新的inet_bind_bucket必须成功 */
	if (!tb && (tb = inet_bind_bucket_create(hashinfo->bind_bucket_cachep,
					net, head, snum)) == NULL)
		goto fail_unlock;
    /* 一个刚分配的tb，owners list当让应该是空的啊
     * TODO： 为什么还有这个if条件在这里  */
	if (hlist_empty(&tb->owners)) {
		if (sk->sk_reuse && sk->sk_state != TCP_LISTEN)
            /* 设置标记，便于后续socket在bind时快速完成能否reuse的判断 */
			tb->fastreuse = 1;
		else
			tb->fastreuse = 0;
		if (sk->sk_reuseport) {
			tb->fastreuseport = 1;
			tb->fastuid = uid;
		} else
			tb->fastreuseport = 0;
	} else {
		if (tb->fastreuse &&
		    (!sk->sk_reuse || sk->sk_state == TCP_LISTEN))
			tb->fastreuse = 0;
		if (tb->fastreuseport &&
		    (!sk->sk_reuseport || !uid_eq(tb->fastuid, uid)))
			tb->fastreuseport = 0;
	}
success:
    /* 绑定port成功，将socket与tb的关联建立好 */
	if (!inet_csk(sk)->icsk_bind_hash)
		inet_bind_hash(sk, tb, snum);
	WARN_ON(inet_csk(sk)->icsk_bind_hash != tb);
	ret = 0;

fail_unlock:
	spin_unlock(&head->lock);
fail:
	local_bh_enable();
	return ret;
}
EXPORT_SYMBOL_GPL(inet_csk_get_port);

/*
 * Wait for an incoming connection, avoid race conditions. This must be called
 * with the socket locked.
 */
static int inet_csk_wait_for_connect(struct sock *sk, long timeo)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	DEFINE_WAIT(wait);
	int err;

	/*
	 * True wake-one mechanism for incoming connections: only
	 * one process gets woken up, not the 'whole herd'.
	 * Since we do not 'race & poll' for established sockets
	 * anymore, the common case will execute the loop only once.
	 *
	 * Subtle issue: "add_wait_queue_exclusive()" will be added
	 * after any current non-exclusive waiters, and we know that
	 * it will always _stay_ after any new non-exclusive waiters
	 * because all non-exclusive waiters are added at the
	 * beginning of the wait-queue. As such, it's ok to "drop"
	 * our exclusiveness temporarily when we get woken up without
	 * having to remove and re-insert us on the wait queue.
	 */
	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);
		if (reqsk_queue_empty(&icsk->icsk_accept_queue))
			timeo = schedule_timeout(timeo);
		lock_sock(sk);
		err = 0;
		if (!reqsk_queue_empty(&icsk->icsk_accept_queue))
			break;
		err = -EINVAL;
		if (sk->sk_state != TCP_LISTEN)
			break;
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			break;
		err = -EAGAIN;
		if (!timeo)
			break;
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

/*
 * This will accept the next outstanding connection.
 */
struct sock *inet_csk_accept(struct sock *sk, int flags, int *err)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct sock *newsk;
	struct request_sock *req;
	int error;

	lock_sock(sk);

	/* We need to make sure that this socket is listening,
	 * and that it has something pending.
	 */
	error = -EINVAL;
	if (sk->sk_state != TCP_LISTEN)
		goto out_err;

	/* Find already established connection */
	if (reqsk_queue_empty(queue)) {
		long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

		/* If this is a non blocking socket don't sleep */
		error = -EAGAIN;
		if (!timeo)
			goto out_err;

		error = inet_csk_wait_for_connect(sk, timeo);
		if (error)
			goto out_err;
	}
	req = reqsk_queue_remove(queue);
	newsk = req->sk;

	sk_acceptq_removed(sk);
	if (sk->sk_protocol == IPPROTO_TCP && queue->fastopenq != NULL) {
		spin_lock_bh(&queue->fastopenq->lock);
		if (tcp_rsk(req)->listener) {
			/* We are still waiting for the final ACK from 3WHS
			 * so can't free req now. Instead, we set req->sk to
			 * NULL to signify that the child socket is taken
			 * so reqsk_fastopen_remove() will free the req
			 * when 3WHS finishes (or is aborted).
			 */
			req->sk = NULL;
			req = NULL;
		}
		spin_unlock_bh(&queue->fastopenq->lock);
	}
out:
	release_sock(sk);
	if (req)
		__reqsk_free(req);
	return newsk;
out_err:
	newsk = NULL;
	req = NULL;
	*err = error;
	goto out;
}
EXPORT_SYMBOL(inet_csk_accept);

/*
 * Using different timers for retransmit, delayed acks and probes
 * We may wish use just one timer maintaining a list of expire jiffies
 * to optimize.
 */
/* 在该函数中设置各个具体重传定时器的处理函数 */
void inet_csk_init_xmit_timers(struct sock *sk,
			       void (*retransmit_handler)(unsigned long),
			       void (*delack_handler)(unsigned long),
			       void (*keepalive_handler)(unsigned long))
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	setup_timer(&icsk->icsk_retransmit_timer, retransmit_handler,
			(unsigned long)sk);
	setup_timer(&icsk->icsk_delack_timer, delack_handler,
			(unsigned long)sk);
	setup_timer(&sk->sk_timer, keepalive_handler, (unsigned long)sk);
	icsk->icsk_pending = icsk->icsk_ack.pending = 0;
}
EXPORT_SYMBOL(inet_csk_init_xmit_timers);

/* 关闭定时器 */
void inet_csk_clear_xmit_timers(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_pending = icsk->icsk_ack.pending = icsk->icsk_ack.blocked = 0;

	sk_stop_timer(sk, &icsk->icsk_retransmit_timer);
	sk_stop_timer(sk, &icsk->icsk_delack_timer);
	sk_stop_timer(sk, &sk->sk_timer);
}
EXPORT_SYMBOL(inet_csk_clear_xmit_timers);

void inet_csk_delete_keepalive_timer(struct sock *sk)
{
	sk_stop_timer(sk, &sk->sk_timer);
}
EXPORT_SYMBOL(inet_csk_delete_keepalive_timer);

void inet_csk_reset_keepalive_timer(struct sock *sk, unsigned long len)
{
	sk_reset_timer(sk, &sk->sk_timer, jiffies + len);
}
EXPORT_SYMBOL(inet_csk_reset_keepalive_timer);

struct dst_entry *inet_csk_route_req(struct sock *sk,
				     struct flowi4 *fl4,
				     const struct request_sock *req)
{
	struct rtable *rt;
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct ip_options_rcu *opt = inet_rsk(req)->opt;
	struct net *net = sock_net(sk);
	int flags = inet_sk_flowi_flags(sk);

	flowi4_init_output(fl4, sk->sk_bound_dev_if, sk->sk_mark,
			   RT_CONN_FLAGS(sk), RT_SCOPE_UNIVERSE,
			   sk->sk_protocol,
			   flags,
			   (opt && opt->opt.srr) ? opt->opt.faddr : ireq->rmt_addr,
			   ireq->loc_addr, ireq->rmt_port, inet_sk(sk)->inet_sport);
	security_req_classify_flow(req, flowi4_to_flowi(fl4));
	rt = ip_route_output_flow(net, fl4, sk);
	if (IS_ERR(rt))
		goto no_route;
	if (opt && opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto route_err;
	return &rt->dst;

route_err:
	ip_rt_put(rt);
no_route:
	IP_INC_STATS_BH(net, IPSTATS_MIB_OUTNOROUTES);
	return NULL;
}
EXPORT_SYMBOL_GPL(inet_csk_route_req);

struct dst_entry *inet_csk_route_child_sock(struct sock *sk,
					    struct sock *newsk,
					    const struct request_sock *req)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	struct inet_sock *newinet = inet_sk(newsk);
	struct ip_options_rcu *opt;
	struct net *net = sock_net(sk);
	struct flowi4 *fl4;
	struct rtable *rt;

	fl4 = &newinet->cork.fl.u.ip4;

	rcu_read_lock();
	opt = rcu_dereference(newinet->inet_opt);
	flowi4_init_output(fl4, sk->sk_bound_dev_if, sk->sk_mark,
			   RT_CONN_FLAGS(sk), RT_SCOPE_UNIVERSE,
			   sk->sk_protocol, inet_sk_flowi_flags(sk),
			   (opt && opt->opt.srr) ? opt->opt.faddr : ireq->rmt_addr,
			   ireq->loc_addr, ireq->rmt_port, inet_sk(sk)->inet_sport);
	security_req_classify_flow(req, flowi4_to_flowi(fl4));
	rt = ip_route_output_flow(net, fl4, sk);
	if (IS_ERR(rt))
		goto no_route;
	if (opt && opt->opt.is_strictroute && rt->rt_uses_gateway)
		goto route_err;
	rcu_read_unlock();
	return &rt->dst;

route_err:
	ip_rt_put(rt);
no_route:
	rcu_read_unlock();
	IP_INC_STATS_BH(net, IPSTATS_MIB_OUTNOROUTES);
	return NULL;
}
EXPORT_SYMBOL_GPL(inet_csk_route_child_sock);

static inline u32 inet_synq_hash(const __be32 raddr, const __be16 rport,
				 const u32 rnd, const u32 synq_hsize)
{
	return jhash_2words((__force u32)raddr, (__force u32)rport, rnd) & (synq_hsize - 1);
}

#if IS_ENABLED(CONFIG_IPV6)
#define AF_INET_FAMILY(fam) ((fam) == AF_INET)
#else
#define AF_INET_FAMILY(fam) 1
#endif

struct request_sock *inet_csk_search_req(const struct sock *sk,
					 struct request_sock ***prevp,
					 const __be16 rport, const __be32 raddr,
					 const __be32 laddr)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct listen_sock *lopt = icsk->icsk_accept_queue.listen_opt;
	struct request_sock *req, **prev;

	for (prev = &lopt->syn_table[inet_synq_hash(raddr, rport, lopt->hash_rnd,
						    lopt->nr_table_entries)];
	     (req = *prev) != NULL;
	     prev = &req->dl_next) {
		const struct inet_request_sock *ireq = inet_rsk(req);

		if (ireq->rmt_port == rport &&
		    ireq->rmt_addr == raddr &&
		    ireq->loc_addr == laddr &&
		    AF_INET_FAMILY(req->rsk_ops->family)) {
			WARN_ON(req->sk);
			*prevp = prev;
			break;
		}
	}

	return req;
}
EXPORT_SYMBOL_GPL(inet_csk_search_req);

void inet_csk_reqsk_queue_hash_add(struct sock *sk, struct request_sock *req,
				   unsigned long timeout)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct listen_sock *lopt = icsk->icsk_accept_queue.listen_opt;
	const u32 h = inet_synq_hash(inet_rsk(req)->rmt_addr, inet_rsk(req)->rmt_port,
				     lopt->hash_rnd, lopt->nr_table_entries);

	reqsk_queue_hash_req(&icsk->icsk_accept_queue, h, req, timeout);
	inet_csk_reqsk_queue_added(sk, timeout);
}
EXPORT_SYMBOL_GPL(inet_csk_reqsk_queue_hash_add);

/* Only thing we need from tcp.h */
extern int sysctl_tcp_synack_retries;


/* Decide when to expire the request and when to resend SYN-ACK */
/* 这里决定request是否过期，也是用num_timeout判断，而不是num_retrans判断
 * expire表示是否等了足够的时间，为true则意味着要删掉request sock
 * resend表示是否需要重传syn/ack
 * thresh是通过sysctl_tcp_synack_retries计算得到的阈值
 */ 
static inline void syn_ack_recalc(struct request_sock *req, const int thresh,
				  const int max_retries,
				  const u8 rskq_defer_accept,
				  int *expire, int *resend)
{
    /* 如果用户程序未指定defer_accept时间，则肯定要重传syn/ack */
	if (!rskq_defer_accept) {
		*expire = req->num_timeout >= thresh;   /* 超时次数超过上限则判断过期 */
		*resend = 1;
		return;
	}

    /* 下面的代码都是在defer_accept开启的情况下才会执行的,
     * max_retries就是defer_accept允许的超时次数 */

    /* 1. 如果没有收到三次握手的最后一个ACK(!inet_rsk(req)->acked为真),
     * 则只要超时次数超过上限，则判定为过期
     * 2.
     * 如果已经收到过三次握手的最后一个ACK，同时超时次数也超过了defer_accept允许的值,
     * 也超过了上限，则判定为过期 */
    /* TODO: 可见max_retries并没有什么用啊，因为在用到它的时候，它只会等于rskq_defer_accept */
	*expire = req->num_timeout >= thresh &&     
		  (!inet_rsk(req)->acked || req->num_timeout >= max_retries);
	/*
	 * Do not resend while waiting for data after ACK,
	 * start to resend on end of deferring period to give
	 * last chance for data or ACK to create established socket.
	 */
    /* 1. 如果已经开启了defer_accept，如果没有收到三次握手的最后一个ACK包，当然要重传syn/ack
     * 2. 如果已经收到了最后一个ACK包，那么仅在最后一次未导致expire的timeout发生时进行重传
     *      TODO: 但这样会不会有BUG ？
     *          比如一个攻击者在攻击时，每次收到syn/ack时都返回一个合法的bare
     *          ack来完成三次握手，那么不就导致这个request sock一直存活吗？
     */
	*resend = !inet_rsk(req)->acked ||
		  req->num_timeout >= rskq_defer_accept - 1;
}

/* 重传一个syn/ack包，冲床成功则num_retrans加1 */
int inet_rtx_syn_ack(struct sock *parent, struct request_sock *req)
{
	int err = req->rsk_ops->rtx_syn_ack(parent, req);

    /* req->num_retrans记录的是synack包的重传次数 */
	if (!err)
		req->num_retrans++;
	return err;
}
EXPORT_SYMBOL(inet_rtx_syn_ack);

void inet_csk_reqsk_queue_prune(struct sock *parent,
				const unsigned long interval,
				const unsigned long timeout,
				const unsigned long max_rto)
{
	struct inet_connection_sock *icsk = inet_csk(parent);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct listen_sock *lopt = queue->listen_opt;
	int max_retries = icsk->icsk_syn_retries ? : sysctl_tcp_synack_retries;
	int thresh = max_retries;
	unsigned long now = jiffies;
	struct request_sock **reqp, *req;
	int i, budget;

	if (lopt == NULL || lopt->qlen == 0)
		return;

	/* Normally all the openreqs are young and become mature
	 * (i.e. converted to established socket) for first timeout.
	 * If synack was not acknowledged for 1 second, it means
	 * one of the following things: synack was lost, ack was lost,
	 * rtt is high or nobody planned to ack (i.e. synflood).
	 * When server is a bit loaded, queue is populated with old
	 * open requests, reducing effective size of queue.
	 * When server is well loaded, queue size reduces to zero
	 * after several minutes of work. It is not synflood,
	 * it is normal operation. The solution is pruning
	 * too old entries overriding normal timeout, when
	 * situation becomes dangerous.
	 *
	 * Essentially, we reserve half of room for young
	 * embrions; and abort old ones without pity, if old
	 * ones are about to clog our table.
	 */
	if (lopt->qlen>>(lopt->max_qlen_log-1)) {
		int young = (lopt->qlen_young<<1);

		while (thresh > 2) {
			if (lopt->qlen < young)
				break;
			thresh--;
			young <<= 1;
		}
	}

    /* 如果用户设置了defer accept，那么将max_retries设置成该值 */
	if (queue->rskq_defer_accept)
		max_retries = queue->rskq_defer_accept;

	budget = 2 * (lopt->nr_table_entries / (timeout / interval));
	i = lopt->clock_hand;

	do {
		reqp=&lopt->syn_table[i];
		while ((req = *reqp) != NULL) {
			if (time_after_eq(now, req->expires)) {
				int expire = 0, resend = 0;

				syn_ack_recalc(req, thresh, max_retries,
					       queue->rskq_defer_accept,
					       &expire, &resend);
				req->rsk_ops->syn_ack_timeout(parent, req);
				if (!expire &&
				    (!resend ||
				     !inet_rtx_syn_ack(parent, req) ||
				     inet_rsk(req)->acked)) {
					unsigned long timeo;

					if (req->num_timeout++ == 0)
						lopt->qlen_young--;
					timeo = min(timeout << req->num_timeout,
						    max_rto);
                    /* 设置expires值使用num_timeout进行指数回避，而不是num_retrans */
					req->expires = now + timeo;
					reqp = &req->dl_next;
					continue;
				}

				/* Drop this request */
				inet_csk_reqsk_queue_unlink(parent, req, reqp);
				reqsk_queue_removed(queue, req);
				reqsk_free(req);
				continue;
			}
			reqp = &req->dl_next;
		}

		i = (i + 1) & (lopt->nr_table_entries - 1);

	} while (--budget > 0);

	lopt->clock_hand = i;

	if (lopt->qlen)
		inet_csk_reset_keepalive_timer(parent, interval);
}
EXPORT_SYMBOL_GPL(inet_csk_reqsk_queue_prune);

/**
 *	inet_csk_clone_lock - clone an inet socket, and lock its clone
 *	@sk: the socket to clone
 *	@req: request_sock
 *	@priority: for allocation (%GFP_KERNEL, %GFP_ATOMIC, etc)
 *
 *	Caller must unlock socket even in error path (bh_unlock_sock(newsk))
 */
struct sock *inet_csk_clone_lock(const struct sock *sk,
				 const struct request_sock *req,
				 const gfp_t priority)
{
	struct sock *newsk = sk_clone_lock(sk, priority);

	if (newsk != NULL) {
		struct inet_connection_sock *newicsk = inet_csk(newsk);

		newsk->sk_state = TCP_SYN_RECV;
		newicsk->icsk_bind_hash = NULL;

		inet_sk(newsk)->inet_dport = inet_rsk(req)->rmt_port;
		inet_sk(newsk)->inet_num = ntohs(inet_rsk(req)->loc_port);
		inet_sk(newsk)->inet_sport = inet_rsk(req)->loc_port;
		newsk->sk_write_space = sk_stream_write_space;

		newicsk->icsk_retransmits = 0;
		newicsk->icsk_backoff	  = 0;
		newicsk->icsk_probes_out  = 0;

		/* Deinitialize accept_queue to trap illegal accesses. */
		memset(&newicsk->icsk_accept_queue, 0, sizeof(newicsk->icsk_accept_queue));

		security_inet_csk_clone(newsk, req);
	}
	return newsk;
}
EXPORT_SYMBOL_GPL(inet_csk_clone_lock);

/*
 * At this point, there should be no process reference to this
 * socket, and thus no user references at all.  Therefore we
 * can assume the socket waitqueue is inactive and nobody will
 * try to jump onto it.
 */
void inet_csk_destroy_sock(struct sock *sk)
{
	WARN_ON(sk->sk_state != TCP_CLOSE);
	WARN_ON(!sock_flag(sk, SOCK_DEAD));

	/* It cannot be in hash table! */
	WARN_ON(!sk_unhashed(sk));

	/* If it has not 0 inet_sk(sk)->inet_num, it must be bound */
	WARN_ON(inet_sk(sk)->inet_num && !inet_csk(sk)->icsk_bind_hash);

	sk->sk_prot->destroy(sk);

	sk_stream_kill_queues(sk);

	xfrm_sk_free_policy(sk);

	sk_refcnt_debug_release(sk);

	percpu_counter_dec(sk->sk_prot->orphan_count);
	sock_put(sk);
}
EXPORT_SYMBOL(inet_csk_destroy_sock);

/* This function allows to force a closure of a socket after the call to
 * tcp/dccp_create_openreq_child().
 */
void inet_csk_prepare_forced_close(struct sock *sk)
	__releases(&sk->sk_lock.slock)
{
	/* sk_clone_lock locked the socket and set refcnt to 2 */
	bh_unlock_sock(sk);
	sock_put(sk);

	/* The below has to be done to allow calling inet_csk_destroy_sock */
	sock_set_flag(sk, SOCK_DEAD);
	percpu_counter_inc(sk->sk_prot->orphan_count);
	inet_sk(sk)->inet_num = 0;
}
EXPORT_SYMBOL(inet_csk_prepare_forced_close);

int inet_csk_listen_start(struct sock *sk, const int nr_table_entries)
{
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int rc = reqsk_queue_alloc(&icsk->icsk_accept_queue, nr_table_entries);

	if (rc != 0)
		return rc;

	sk->sk_max_ack_backlog = 0;
	sk->sk_ack_backlog = 0;
	inet_csk_delack_init(sk);

	/* There is race window here: we announce ourselves listening,
	 * but this transition is still not validated by get_port().
	 * It is OK, because this socket enters to hash table only
	 * after validation is complete.
	 */
	sk->sk_state = TCP_LISTEN;
	if (!sk->sk_prot->get_port(sk, inet->inet_num)) {
		inet->inet_sport = htons(inet->inet_num);

		sk_dst_reset(sk);
		sk->sk_prot->hash(sk);

		return 0;
	}

	sk->sk_state = TCP_CLOSE;
	__reqsk_queue_destroy(&icsk->icsk_accept_queue);
	return -EADDRINUSE;
}
EXPORT_SYMBOL_GPL(inet_csk_listen_start);

/*
 *	This routine closes sockets which have been at least partially
 *	opened, but not yet accepted.
 */
void inet_csk_listen_stop(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
	struct request_sock *acc_req;
	struct request_sock *req;

	inet_csk_delete_keepalive_timer(sk);

	/* make all the listen_opt local to us */
	acc_req = reqsk_queue_yank_acceptq(queue);

	/* Following specs, it would be better either to send FIN
	 * (and enter FIN-WAIT-1, it is normal close)
	 * or to send active reset (abort).
	 * Certainly, it is pretty dangerous while synflood, but it is
	 * bad justification for our negligence 8)
	 * To be honest, we are not able to make either
	 * of the variants now.			--ANK
	 */
	reqsk_queue_destroy(queue);

	while ((req = acc_req) != NULL) {
		struct sock *child = req->sk;

		acc_req = req->dl_next;

		local_bh_disable();
		bh_lock_sock(child);
		WARN_ON(sock_owned_by_user(child));
		sock_hold(child);

		sk->sk_prot->disconnect(child, O_NONBLOCK);

		sock_orphan(child);

		percpu_counter_inc(sk->sk_prot->orphan_count);

		if (sk->sk_protocol == IPPROTO_TCP && tcp_rsk(req)->listener) {
			BUG_ON(tcp_sk(child)->fastopen_rsk != req);
			BUG_ON(sk != tcp_rsk(req)->listener);

			/* Paranoid, to prevent race condition if
			 * an inbound pkt destined for child is
			 * blocked by sock lock in tcp_v4_rcv().
			 * Also to satisfy an assertion in
			 * tcp_v4_destroy_sock().
			 */
			tcp_sk(child)->fastopen_rsk = NULL;
			sock_put(sk);
		}
		inet_csk_destroy_sock(child);

		bh_unlock_sock(child);
		local_bh_enable();
		sock_put(child);

		sk_acceptq_removed(sk);
		__reqsk_free(req);
	}
	if (queue->fastopenq != NULL) {
		/* Free all the reqs queued in rskq_rst_head. */
		spin_lock_bh(&queue->fastopenq->lock);
		acc_req = queue->fastopenq->rskq_rst_head;
		queue->fastopenq->rskq_rst_head = NULL;
		spin_unlock_bh(&queue->fastopenq->lock);
		while ((req = acc_req) != NULL) {
			acc_req = req->dl_next;
			__reqsk_free(req);
		}
	}
	WARN_ON(sk->sk_ack_backlog);
}
EXPORT_SYMBOL_GPL(inet_csk_listen_stop);

void inet_csk_addr2sockaddr(struct sock *sk, struct sockaddr *uaddr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	const struct inet_sock *inet = inet_sk(sk);

	sin->sin_family		= AF_INET;
	sin->sin_addr.s_addr	= inet->inet_daddr;
	sin->sin_port		= inet->inet_dport;
}
EXPORT_SYMBOL_GPL(inet_csk_addr2sockaddr);

#ifdef CONFIG_COMPAT
int inet_csk_compat_getsockopt(struct sock *sk, int level, int optname,
			       char __user *optval, int __user *optlen)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_af_ops->compat_getsockopt != NULL)
		return icsk->icsk_af_ops->compat_getsockopt(sk, level, optname,
							    optval, optlen);
	return icsk->icsk_af_ops->getsockopt(sk, level, optname,
					     optval, optlen);
}
EXPORT_SYMBOL_GPL(inet_csk_compat_getsockopt);

int inet_csk_compat_setsockopt(struct sock *sk, int level, int optname,
			       char __user *optval, unsigned int optlen)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_af_ops->compat_setsockopt != NULL)
		return icsk->icsk_af_ops->compat_setsockopt(sk, level, optname,
							    optval, optlen);
	return icsk->icsk_af_ops->setsockopt(sk, level, optname,
					     optval, optlen);
}
EXPORT_SYMBOL_GPL(inet_csk_compat_setsockopt);
#endif

static struct dst_entry *inet_csk_rebuild_route(struct sock *sk, struct flowi *fl)
{
	const struct inet_sock *inet = inet_sk(sk);
	const struct ip_options_rcu *inet_opt;
	__be32 daddr = inet->inet_daddr;
	struct flowi4 *fl4;
	struct rtable *rt;

	rcu_read_lock();
	inet_opt = rcu_dereference(inet->inet_opt);
	if (inet_opt && inet_opt->opt.srr)
		daddr = inet_opt->opt.faddr;
	fl4 = &fl->u.ip4;
	rt = ip_route_output_ports(sock_net(sk), fl4, sk, daddr,
				   inet->inet_saddr, inet->inet_dport,
				   inet->inet_sport, sk->sk_protocol,
				   RT_CONN_FLAGS(sk), sk->sk_bound_dev_if);
	if (IS_ERR(rt))
		rt = NULL;
	if (rt)
		sk_setup_caps(sk, &rt->dst);
	rcu_read_unlock();

	return &rt->dst;
}

struct dst_entry *inet_csk_update_pmtu(struct sock *sk, u32 mtu)
{
	struct dst_entry *dst = __sk_dst_check(sk, 0);
	struct inet_sock *inet = inet_sk(sk);

	if (!dst) {
		dst = inet_csk_rebuild_route(sk, &inet->cork.fl);
		if (!dst)
			goto out;
	}
	dst->ops->update_pmtu(dst, sk, NULL, mtu);

	dst = __sk_dst_check(sk, 0);
	if (!dst)
		dst = inet_csk_rebuild_route(sk, &inet->cork.fl);
out:
	return dst;
}
EXPORT_SYMBOL_GPL(inet_csk_update_pmtu);
