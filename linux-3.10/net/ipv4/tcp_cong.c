/*
 * Plugable TCP congestion control support and newReno
 * congestion control.
 * Based on ideas from I/O scheduler support and Web100.
 *
 * Copyright (C) 2005 Stephen Hemminger <shemminger@osdl.org>
 */

/* 模块化的拥塞控制算法框架实现 */

#define pr_fmt(fmt) "TCP: " fmt

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/gfp.h>
#include <net/tcp.h>

int sysctl_tcp_max_ssthresh = 0;

static DEFINE_SPINLOCK(tcp_cong_list_lock);
static LIST_HEAD(tcp_cong_list);

/* Simple linear search, don't expect many entries! */
/* 在已经加载的拥塞控制算法模块列表中，根据name找到特定的某一个拥塞控制算法 */
static struct tcp_congestion_ops *tcp_ca_find(const char *name)
{
	struct tcp_congestion_ops *e;

	list_for_each_entry_rcu(e, &tcp_cong_list, list) {
		if (strcmp(e->name, name) == 0)
			return e;
	}

	return NULL;
}

/*
 * Attach new congestion control algorithm to the list
 * of available options.
 */
int tcp_register_congestion_control(struct tcp_congestion_ops *ca)
{
	int ret = 0;

	/* all algorithms must implement ssthresh and cong_avoid ops */
	if (!ca->ssthresh || !ca->cong_avoid) {
		pr_err("%s does not implement required ops\n", ca->name);
		return -EINVAL;
	}

	spin_lock(&tcp_cong_list_lock);
    /* 如果已经注册过同名的算法，则放弃加载并报错 */
	if (tcp_ca_find(ca->name)) {
		pr_notice("%s already registered\n", ca->name);
		ret = -EEXIST;
	} else {
		list_add_tail_rcu(&ca->list, &tcp_cong_list);
		pr_info("%s registered\n", ca->name);
	}
	spin_unlock(&tcp_cong_list_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(tcp_register_congestion_control);

/*
 * Remove congestion control algorithm, called from
 * the module's remove function.  Module ref counts are used
 * to ensure that this can't be done till all sockets using
 * that method are closed.
 */
void tcp_unregister_congestion_control(struct tcp_congestion_ops *ca)
{
	spin_lock(&tcp_cong_list_lock);
	list_del_rcu(&ca->list);
	spin_unlock(&tcp_cong_list_lock);
}
EXPORT_SYMBOL_GPL(tcp_unregister_congestion_control);

/* Assign choice of congestion control. */
void tcp_init_congestion_control(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_congestion_ops *ca;

	/* if no choice made yet assign the current value set as default */
    /* 如果icsk_ca_ops还是默认的(name为空的拥塞算法，本质是reno)，说明用户没有通过setsockopt去指定拥塞控制算法，从而就使用sysctl配置好的算法
     * 具体就是会遍历tcp_cong_list，从中取出第一个"能用"的，用于初始化某条TCP流特定的拥塞控制算法 */
	if (icsk->icsk_ca_ops == &tcp_init_congestion_ops) {
		rcu_read_lock();
		list_for_each_entry_rcu(ca, &tcp_cong_list, list) {
			if (try_module_get(ca->owner)) {
				icsk->icsk_ca_ops = ca;
				break;
			}

			/* fallback to next available */
		}
		rcu_read_unlock();
	}

    /* 如果被选中的拥塞控制算法有自己需要执行的初始化动作，则执行它 */
	if (icsk->icsk_ca_ops->init)
		icsk->icsk_ca_ops->init(sk);
}

/* Manage refcounts on socket close. */
void tcp_cleanup_congestion_control(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ca_ops->release)
		icsk->icsk_ca_ops->release(sk);
	module_put(icsk->icsk_ca_ops->owner);
}

/* Used by sysctl to change default congestion control */
/* 通过sysctl改变系统默认的拥塞控制算法
 * 本质就是将指定的拥塞控制算法放到tcp_cong_list的第一个位置 */
int tcp_set_default_congestion_control(const char *name)
{
	struct tcp_congestion_ops *ca;
	int ret = -ENOENT;

	spin_lock(&tcp_cong_list_lock);
	ca = tcp_ca_find(name);
#ifdef CONFIG_MODULES
	if (!ca && capable(CAP_NET_ADMIN)) {
		spin_unlock(&tcp_cong_list_lock);

		request_module("tcp_%s", name);
		spin_lock(&tcp_cong_list_lock);
		ca = tcp_ca_find(name);
	}
#endif

    /* 如果找到了指定name的拥塞控制算法，就将它移到tcp_cong_list的第一个位置，
     * 这样在初始化拥塞控制算法的时候，就会选中这一个算法 */
	if (ca) {
		ca->flags |= TCP_CONG_NON_RESTRICTED;	/* default is always allowed */
		list_move(&ca->list, &tcp_cong_list);
		ret = 0;
	}
	spin_unlock(&tcp_cong_list_lock);

	return ret;
}

/* Set default value from kernel configuration at bootup */
/* 设置默认的拥塞控制算法，目前默认的是cubic */
static int __init tcp_congestion_default(void)
{
	return tcp_set_default_congestion_control(CONFIG_DEFAULT_TCP_CONG);
}
late_initcall(tcp_congestion_default);


/* Build string with list of available congestion control values */
void tcp_get_available_congestion_control(char *buf, size_t maxlen)
{
	struct tcp_congestion_ops *ca;
	size_t offs = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(ca, &tcp_cong_list, list) {
		offs += snprintf(buf + offs, maxlen - offs,
				 "%s%s",
				 offs == 0 ? "" : " ", ca->name);

	}
	rcu_read_unlock();
}

/* Get current default congestion control */
void tcp_get_default_congestion_control(char *name)
{
	struct tcp_congestion_ops *ca;
	/* We will always have reno... */
	BUG_ON(list_empty(&tcp_cong_list));

	rcu_read_lock();
	ca = list_entry(tcp_cong_list.next, struct tcp_congestion_ops, list);
	strncpy(name, ca->name, TCP_CA_NAME_MAX);
	rcu_read_unlock();
}

/* Built list of non-restricted congestion control values */
void tcp_get_allowed_congestion_control(char *buf, size_t maxlen)
{
	struct tcp_congestion_ops *ca;
	size_t offs = 0;

	*buf = '\0';
	rcu_read_lock();
	list_for_each_entry_rcu(ca, &tcp_cong_list, list) {
		if (!(ca->flags & TCP_CONG_NON_RESTRICTED))
			continue;
		offs += snprintf(buf + offs, maxlen - offs,
				 "%s%s",
				 offs == 0 ? "" : " ", ca->name);

	}
	rcu_read_unlock();
}

/* Change list of non-restricted congestion control */
int tcp_set_allowed_congestion_control(char *val)
{
	struct tcp_congestion_ops *ca;
	char *saved_clone, *clone, *name;
	int ret = 0;

	saved_clone = clone = kstrdup(val, GFP_USER);
	if (!clone)
		return -ENOMEM;

	spin_lock(&tcp_cong_list_lock);
	/* pass 1 check for bad entries */
	while ((name = strsep(&clone, " ")) && *name) {
		ca = tcp_ca_find(name);
		if (!ca) {
			ret = -ENOENT;
			goto out;
		}
	}

	/* pass 2 clear old values */
	list_for_each_entry_rcu(ca, &tcp_cong_list, list)
		ca->flags &= ~TCP_CONG_NON_RESTRICTED;

	/* pass 3 mark as allowed */
	while ((name = strsep(&val, " ")) && *name) {
		ca = tcp_ca_find(name);
		WARN_ON(!ca);
		if (ca)
			ca->flags |= TCP_CONG_NON_RESTRICTED;
	}
out:
	spin_unlock(&tcp_cong_list_lock);
	kfree(saved_clone);

	return ret;
}


/* Change congestion control for socket */
/* 提供给setsockopt()的接口，用于应用程序指定想使用的拥塞控制算法 */
int tcp_set_congestion_control(struct sock *sk, const char *name)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_congestion_ops *ca;
	int err = 0;

	rcu_read_lock();
	ca = tcp_ca_find(name);

	/* no change asking for existing value */
    /* 如果想用的就是默认的，则直接返回即可 */
	if (ca == icsk->icsk_ca_ops)
		goto out;

#ifdef CONFIG_MODULES
	/* not found attempt to autoload module */
	if (!ca && capable(CAP_NET_ADMIN)) {
		rcu_read_unlock();
		request_module("tcp_%s", name);
		rcu_read_lock();
		ca = tcp_ca_find(name);
	}
#endif
    /* 如果没找到，返回错误 */
	if (!ca)
		err = -ENOENT;  /* 错误码：未找到文件或目录 */

    /* 如果没有权限使用，则返回错误 */
	else if (!((ca->flags & TCP_CONG_NON_RESTRICTED) ||
		   ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN)))
		err = -EPERM;   /* 错误码：操作不被允许 */

    /* 如果获取不到，则返回错误 */
	else if (!try_module_get(ca->owner))
		err = -EBUSY;   /* 错误码: 资源正被占用 */

	else {
        /* 先清理现有拥塞控制算法 */
		tcp_cleanup_congestion_control(sk);
        /* 再设置新的，指定的拥塞控制算法 */
		icsk->icsk_ca_ops = ca;

		if (sk->sk_state != TCP_CLOSE && icsk->icsk_ca_ops->init)
			icsk->icsk_ca_ops->init(sk);
	}
 out:
	rcu_read_unlock();
	return err;
}

/* RFC2861 Check whether we are limited by application or congestion window
 * This is the inverse of cwnd check in tcp_tso_should_defer
 */
/* 判断cwnd是否被充分利用 */
bool tcp_is_cwnd_limited(const struct sock *sk, u32 in_flight)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 left;

    /* 如果in_flight数量超过cwnd，说明cwnd已被充分利用，可以考虑继续增长cwnd */
	if (in_flight >= tp->snd_cwnd)
		return true;

	left = tp->snd_cwnd - in_flight;
    /* TODO: GSO相关内容 */
	if (sk_can_gso(sk) &&
	    left * sysctl_tcp_tso_win_divisor < tp->snd_cwnd &&
	    left * tp->mss_cache < sk->sk_gso_max_size &&
	    left < sk->sk_gso_max_segs)
		return true;
	return left <= tcp_max_tso_deferred_mss(tp);
}
EXPORT_SYMBOL_GPL(tcp_is_cwnd_limited);

/*
 * Slow start is used when congestion window is less than slow start
 * threshold. This version implements the basic RFC2581 version
 * and optionally supports:
 * 	RFC3742 Limited Slow Start  	  - growth limited to max_ssthresh
 *	RFC3465 Appropriate Byte Counting - growth limited by bytes acknowledged
 */
/* 慢启动增加cwnd，每收到一个ACK调用一次，但通过snd_cwnd_cnt是否超过snd_cwnd来判断是否需要增加cwnd */
void tcp_slow_start(struct tcp_sock *tp)
{
	int cnt; /* increase in packets */
	unsigned int delta = 0;
	u32 snd_cwnd = tp->snd_cwnd;

	if (unlikely(!snd_cwnd)) {
		pr_err_once("snd_cwnd is nul, please report this bug.\n");
		snd_cwnd = 1U;
	}

    /* 如果设置了最大的sshresh，并且cwnd已经超过该值，则限制cwnd的增速 */
	if (sysctl_tcp_max_ssthresh > 0 && tp->snd_cwnd > sysctl_tcp_max_ssthresh)
		cnt = sysctl_tcp_max_ssthresh >> 1;	/* limited slow start */
	else
		cnt = snd_cwnd;				/* exponential increase */

	tp->snd_cwnd_cnt += cnt;    /* 当snd_cwnd_cnt够一个snd_cwnd时，snd_cwnd需要增长1 */
	while (tp->snd_cwnd_cnt >= snd_cwnd) {
		tp->snd_cwnd_cnt -= snd_cwnd;
		delta++;
	}
    /* 增大snd_cwnd，但也受限于snd_cwnd_clamp(一般都很大，不会达到) */
	tp->snd_cwnd = min(snd_cwnd + delta, tp->snd_cwnd_clamp);
}
EXPORT_SYMBOL_GPL(tcp_slow_start);

/* In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w) */
/* Reno算法：在拥塞避免阶段，每一个RTT时间内，cwnd增长1
 * 从而就是每收到一个ACK，cwnd增长1/cwnd，*/
void tcp_cong_avoid_ai(struct tcp_sock *tp, u32 w)
{
    /* w一般传入的就是snd_cwnd */
	if (tp->snd_cwnd_cnt >= w) {
		if (tp->snd_cwnd < tp->snd_cwnd_clamp)
			tp->snd_cwnd++;
		tp->snd_cwnd_cnt = 0;
	} else {
        /* 注意这里，每收到一个ACK时，snd_cwnd_cnt只增加1，
         * 从而在一个RTT后，这个值应该就是一个cwnd了，
         * 然后就会调用上一个分支将cwnd增长1 */
		tp->snd_cwnd_cnt++;     
	}
}
EXPORT_SYMBOL_GPL(tcp_cong_avoid_ai);

/*
 * TCP Reno congestion control
 * This is special case used for fallback as well.
 */
/* This is Jacobson's slow start and congestion avoidance.
 * SIGCOMM '88, p. 328.
 */
void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);

    /* 判断数据的发送是否受限于cwnd，如果不受限于cwnd(返回false),则直接退出
     * 内在含义就是：如果cwnd已经足够大了，已经没有必要增长cwnd了 */
	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	/* In "safe" area, increase. */
	if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_slow_start(tp);     /* 慢启动 */
	/* In dangerous area, increase slowly. */
	else
		tcp_cong_avoid_ai(tp, tp->snd_cwnd);    /* 拥塞避免 */
}
EXPORT_SYMBOL_GPL(tcp_reno_cong_avoid);

/* Slow start threshold is half the congestion window (min 2) */
/* reno: 发生丢包时，将ssthrehs设置为当前cwnd的一半 */
u32 tcp_reno_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	return max(tp->snd_cwnd >> 1U, 2U);
}
EXPORT_SYMBOL_GPL(tcp_reno_ssthresh);

/* Lower bound on congestion window with halving. */
u32 tcp_reno_min_cwnd(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	return tp->snd_ssthresh/2;
}
EXPORT_SYMBOL_GPL(tcp_reno_min_cwnd);

struct tcp_congestion_ops tcp_reno = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "reno",
	.owner		= THIS_MODULE,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.min_cwnd	= tcp_reno_min_cwnd,
};

/* Initial congestion control used (until SYN)
 * really reno under another name so we can tell difference
 * during tcp_set_default_congestion_control
 */
/*整个TCP协议栈实现中，默认的拥塞控制算法就是RENO算法 */
struct tcp_congestion_ops tcp_init_congestion_ops  = {
	.name		= "",
	.owner		= THIS_MODULE,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.min_cwnd	= tcp_reno_min_cwnd,
};
EXPORT_SYMBOL_GPL(tcp_init_congestion_ops);
