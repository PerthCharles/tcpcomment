/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

#include <linux/module.h>
#include <linux/gfp.h>
#include <net/tcp.h>

int sysctl_tcp_syn_retries __read_mostly = TCP_SYN_RETRIES;
int sysctl_tcp_synack_retries __read_mostly = TCP_SYNACK_RETRIES;
int sysctl_tcp_keepalive_time __read_mostly = TCP_KEEPALIVE_TIME;
int sysctl_tcp_keepalive_probes __read_mostly = TCP_KEEPALIVE_PROBES;
int sysctl_tcp_keepalive_intvl __read_mostly = TCP_KEEPALIVE_INTVL;
int sysctl_tcp_retries1 __read_mostly = TCP_RETR1;
int sysctl_tcp_retries2 __read_mostly = TCP_RETR2;
int sysctl_tcp_orphan_retries __read_mostly;
int sysctl_tcp_thin_linear_timeouts __read_mostly;

/* 如果重传多次后依然没收到对端的响应，则只好关闭socket */
static void tcp_write_err(struct sock *sk)
{
	sk->sk_err = sk->sk_err_soft ? : ETIMEDOUT;
	sk->sk_error_report(sk);

	tcp_done(sk);
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONTIMEOUT);
}

/* Do not allow orphaned sockets to eat all our resources.
 * This is direct violation of TCP specs, but it is required
 * to prevent DoS attacks. It is called when a retransmission timeout
 * or zero probe timeout occurs on orphaned socket.
 *
 * Criteria is still not confirmed experimentally and may change.
 * We kill the socket, if:
 * 1. If number of orphaned sockets exceeds an administratively configured
 *    limit.
 * 2. If we have strong memory pressure.
 */
/* 返回0表示没有out_of_resources, 
 * 返回1表示资源出现不足了，而且socket已经被设置为CLOSE状态 */
static int tcp_out_of_resources(struct sock *sk, int do_reset)
{
	struct tcp_sock *tp = tcp_sk(sk);
    /* shift的含义就是：在判断是否超过上限时，将默认的上限左移shift次，缩小 2^shift倍
     * 所以也就很好理解下面的penalize是什么意思了 */
	int shift = 0;

	/* If peer does not open window for long time, or did not transmit
	 * anything for long time, penalize it. */
	if ((s32)(tcp_time_stamp - tp->lsndtime) > 2*TCP_RTO_MAX || !do_reset)
		shift++;

	/* If some dubious ICMP arrived, penalize even more. */
	if (sk->sk_err_soft)
		shift++;

    /* tcp_check_oom()负责具体的检查orphaned sockets是否超过上限，和内存使用量 */
	if (tcp_check_oom(sk, shift)) {
		/* Catch exceptional cases, when connection requires reset.
		 *      1. Last segment was sent recently. */
        /* 如果最近的一个数据包的发送时间还处在TIMEWAIT_LEN(60s)以内，则需要发送reset
         * 既然本地由于资源不足，想要关闭这个socket，那么自然要发送reset通知对端.
         * 但是如果距离上一次发送数据包已经过去了很久60s，那么"实现者"认为没什么必要发送这个reset
         * TODO：RFC有解释为什么吗 ？ 目前的理解还只是基于现有知识的猜测 */
		if ((s32)(tcp_time_stamp - tp->lsndtime) <= TCP_TIMEWAIT_LEN ||
		    /*  2. Window is closed. */
        /* 如果对端关闭了发送窗口，或者本端已经没有数据在外面，则需要发送reset
         * 这种情况下要主动的发送reset，是因为此时没有条件被动的触发reset */
		    (!tp->snd_wnd && !tp->packets_out))
			do_reset = 1;

		if (do_reset)
			tcp_send_active_reset(sk, GFP_ATOMIC);
		tcp_done(sk);   /* 关闭socket */
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONMEMORY);
		return 1;
	}
	return 0;
}

/* Calculate maximal number or retries on an orphaned socket. */
/* TODO: orphaned socket具体是什么？ 怎么产生的 */
static int tcp_orphan_retries(struct sock *sk, int alive)
{
	int retries = sysctl_tcp_orphan_retries; /* May be zero. */

	/* We know from an ICMP that something is wrong. */
	if (sk->sk_err_soft && !alive)
		retries = 0;

	/* However, if socket sent something recently, select some safe
	 * number of retries. 8 corresponds to >100 seconds with minimal
	 * RTO of 200msec. */
    /* 理解英文注释即可 */
	if (retries == 0 && alive)
		retries = 8;
	return retries;
}

static void tcp_mtu_probing(struct inet_connection_sock *icsk, struct sock *sk)
{
	/* Black hole detection */
	if (sysctl_tcp_mtu_probing) {
		if (!icsk->icsk_mtup.enabled) {
			icsk->icsk_mtup.enabled = 1;
			tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		} else {
			struct tcp_sock *tp = tcp_sk(sk);
			int mss;

			mss = tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low) >> 1;
			mss = min(sysctl_tcp_base_mss, mss);
			mss = max(mss, 68 - tp->tcp_header_len);
			icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, mss);
			tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		}
	}
}

/* This function calculates a "timeout" which is equivalent to the timeout of a
 * TCP connection after "boundary" unsuccessful, exponentially backed-off
 * retransmissions with an initial RTO of TCP_RTO_MIN or TCP_TIMEOUT_INIT if
 * syn_set flag is set.
 */
/* 判断rto重传次数是否超过了boundary
 * 但是：这个函数是将boundary次数转换一个timeout时间来进行判断的
 * timeout时间的计算方法时：为以TCP_RTO_MIN为初始值，进行boundary次指数回避重传需要的时间
 */
static bool retransmits_timed_out(struct sock *sk,
				  unsigned int boundary,
				  unsigned int timeout,
				  bool syn_set)
{
	unsigned int linear_backoff_thresh, start_ts;
    /* 如果是发送syn包，rto_base就设置为1s，否则设置为200ms */
	unsigned int rto_base = syn_set ? TCP_TIMEOUT_INIT : TCP_RTO_MIN;

    /* 如果没有进行过rto 重传，自然返回false */
	if (!inet_csk(sk)->icsk_retransmits)
		return false;

    /* 如果进行过重传，应该会设置重传开始的时间retrans_stamp
     * 如果实在没有，就使用发送队列第一个skb的(重传)发送时间*/
	if (unlikely(!tcp_sk(sk)->retrans_stamp))
		start_ts = TCP_SKB_CB(tcp_write_queue_head(sk))->when;
	else
		start_ts = tcp_sk(sk)->retrans_stamp;

    /* 目前调用该函数的时候，timeout都是设置为0，依然保留该参数可能是代码变更历史原因 */
	if (likely(timeout == 0)) {
        /* 计算从rto_base增长到TCP_RTO_MAX的次数
         * 理解下面的代码，只要记得rto有TCP_RTO_MAX作为上限限制，
         * 故rto的增长方式其实是一个分段函数，想着这点就很好理解了 */
		linear_backoff_thresh = ilog2(TCP_RTO_MAX/rto_base);

		if (boundary <= linear_backoff_thresh)
			timeout = ((2 << boundary) - 1) * rto_base;
		else
			timeout = ((2 << linear_backoff_thresh) - 1) * rto_base +
				(boundary - linear_backoff_thresh) * TCP_RTO_MAX;
	}
    /* 判断进行rto重传的总时间，是否超过了由boundary计算得来的timeout时间 */
	return (tcp_time_stamp - start_ts) >= timeout;
}

/* A write timeout has occurred. Process the after effects. */
/* 计算rto是否已经重传了足够多，足够久，该放弃的时候就得放弃，否则没头了 */
static int tcp_write_timeout(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int retry_until;
	bool do_reset, syn_set = false;

    /* 如果状态处于SYN_SEND或SYN_RECV状态 */
	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
        /* 如果已经不是第一次重传了，则怀疑路由有问题了 */
		if (icsk->icsk_retransmits)
			dst_negative_advice(sk);
        /* 由于synack的重传是会复用keepalive timer的，所以这里仅需要关心syn的重传即可 */
		retry_until = icsk->icsk_syn_retries ? : sysctl_tcp_syn_retries;
		syn_set = true;
	} else {
        /* 判断重传次数是否已经超过sysctl_tcp_retries1次，如果超过了，则担心路由出现问题了，
         * 则要重新选路 */
		if (retransmits_timed_out(sk, sysctl_tcp_retries1, 0, 0)) {
			/* Black hole detection */
			tcp_mtu_probing(icsk, sk);

			dst_negative_advice(sk);
		}

		retry_until = sysctl_tcp_retries2;
		if (sock_flag(sk, SOCK_DEAD)) {
            /* 如果已经是一个orphan的socket，并且它的rto还没有达到120s，则考虑再给它一点活路 */
			const int alive = (icsk->icsk_rto < TCP_RTO_MAX);

			retry_until = tcp_orphan_retries(sk, alive);
            /* TODO：理解发送reset的内在理由 */
			do_reset = alive ||
				!retransmits_timed_out(sk, retry_until, 0, 0);  /* 如果判断没有超过重传次数，则发送reset */

			if (tcp_out_of_resources(sk, do_reset))
				return 1;
		}
	}

    /* 判断重传次数是否超过sysctl_tcp_retries2  -- 当然还可能是tcp_orphan_retires() */
	if (retransmits_timed_out(sk, retry_until,
				  syn_set ? 0 : icsk->icsk_user_timeout, syn_set)) {
		/* Has it gone just too far? */
		tcp_write_err(sk);
		return 1;
	}
	return 0;
}

/* 延迟确认的实际处理函数 */
void tcp_delack_timer_handler(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	sk_mem_reclaim_partial(sk);

    /* 如果连接关闭了，或者延迟确认定时器并未启动，则直接返回 */
	if (sk->sk_state == TCP_CLOSE || !(icsk->icsk_ack.pending & ICSK_ACK_TIMER))
		goto out;

    /* 如果还没有到超时时刻，则重设定时器继续计时 */
	if (time_after(icsk->icsk_ack.timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_delack_timer, icsk->icsk_ack.timeout);
		goto out;
	}
    /* 去除延迟定时器启动标志 */
	icsk->icsk_ack.pending &= ~ICSK_ACK_TIMER;

	if (!skb_queue_empty(&tp->ucopy.prequeue)) {
		struct sk_buff *skb;

        /* 将数据加入prequeue，本来是期待着userspace尽快处理。其中仍有数据，
         * 可能隐含着userspace行文不佳 */
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPSCHEDULERFAILED);

		while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
			sk_backlog_rcv(sk, skb);

		tp->ucopy.memory = 0;
	}

    /* 如果需要发送的被delay的ACK */
	if (inet_csk_ack_scheduled(sk)) {
        /* pingpong变量为1，则表示session是交互式的，也就是数据有来有往
         * 那么既然发生了延迟确认定时器超时，就说明不再是交互式的。
         * 将pingpong设置为0是必须的*/

        /* 如果pingpong已经被设置为零了，还发生了超时，则采用指数回避策略了 */
		if (!icsk->icsk_ack.pingpong) {
			/* Delayed ACK missed: inflate ATO. */
			icsk->icsk_ack.ato = min(icsk->icsk_ack.ato << 1, icsk->icsk_rto);
		} else {
			/* Delayed ACK missed: leave pingpong mode and
			 * deflate ATO.
			 */
			icsk->icsk_ack.pingpong = 0;
			icsk->icsk_ack.ato      = TCP_ATO_MIN;
		}

        /* 立即发送一个delayed ACK
         * 如果分配skb失败，则无法发送ACK，也会再次启动延迟确认定时器
         * 这种情况就可能导致pingpong已经设置为0的情况下，还发生超时 */
		tcp_send_ack(sk);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKS);
	}

out:
	if (sk_under_memory_pressure(sk))
		sk_mem_reclaim(sk);
}

/* 延迟确认定时器的处理函数
 * 如果local在icsk->icsk_ack.timeout时间内都没有要跟着这个被delay的ACK
 * 一块发出去的数据，那么延迟确认定时器就会超时。进而调用这个处理函数
 * 来发送一个纯粹的ACK包
 */
static void tcp_delack_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
        /* 如果此时socket没有被user占用，则调用实际的处理函数 */
		tcp_delack_timer_handler(sk);
	} else {
        /* 如果此时socket被user占用，则将blocked置为1 */
		inet_csk(sk)->icsk_ack.blocked = 1;
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKLOCKED);
        /* 然后通过设置标记，把工作委托给tcp_release_cb()函数
         * 调用流程为: release_sock() -> tcp_release_cb()
         */
		/* deleguate our work to tcp_release_cb() */
		if (!test_and_set_bit(TCP_DELACK_TIMER_DEFERRED, &tcp_sk(sk)->tsq_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}

static void tcp_probe_timer(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int max_probes;

	if (tp->packets_out || !tcp_send_head(sk)) {
		icsk->icsk_probes_out = 0;
		return;
	}

	/* *WARNING* RFC 1122 forbids this
	 *
	 * It doesn't AFAIK, because we kill the retransmit timer -AK
	 *
	 * FIXME: We ought not to do it, Solaris 2.5 actually has fixing
	 * this behaviour in Solaris down as a bug fix. [AC]
	 *
	 * Let me to explain. icsk_probes_out is zeroed by incoming ACKs
	 * even if they advertise zero window. Hence, connection is killed only
	 * if we received no ACKs for normal connection timeout. It is not killed
	 * only because window stays zero for some time, window may be zero
	 * until armageddon and even later. We are in full accordance
	 * with RFCs, only probe timer combines both retransmission timeout
	 * and probe timeout in one bottle.				--ANK
	 */
	max_probes = sysctl_tcp_retries2;

	if (sock_flag(sk, SOCK_DEAD)) {
		const int alive = ((icsk->icsk_rto << icsk->icsk_backoff) < TCP_RTO_MAX);

		max_probes = tcp_orphan_retries(sk, alive);

		if (tcp_out_of_resources(sk, alive || icsk->icsk_probes_out <= max_probes))
			return;
	}

	if (icsk->icsk_probes_out > max_probes) {
		tcp_write_err(sk);
	} else {
		/* Only send another probe if we didn't close things up. */
		tcp_send_probe0(sk);
	}
}

/*
 *	Timer for Fast Open socket to retransmit SYNACK. Note that the
 *	sk here is the child socket, not the parent (listener) socket.
 */
static void tcp_fastopen_synack_timer(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int max_retries = icsk->icsk_syn_retries ? :
	    sysctl_tcp_synack_retries + 1; /* add one more retry for fastopen */
	struct request_sock *req;

	req = tcp_sk(sk)->fastopen_rsk;
	req->rsk_ops->syn_ack_timeout(sk, req);

	if (req->num_timeout >= max_retries) {
		tcp_write_err(sk);
		return;
	}
	/* XXX (TFO) - Unlike regular SYN-ACK retransmit, we ignore error
	 * returned from rtx_syn_ack() to make it more persistent like
	 * regular retransmit because if the child socket has been accepted
	 * it's not good to give up too easily.
	 */
	inet_rtx_syn_ack(sk, req);
	req->num_timeout++;
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
			  TCP_TIMEOUT_INIT << req->num_timeout, TCP_RTO_MAX);
}

/*
 *	The TCP retransmit timer.
 */
/* rto timer的处理函数 */
void tcp_retransmit_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

    /* TODO: fast open相关 */
	if (tp->fastopen_rsk) {
		WARN_ON_ONCE(sk->sk_state != TCP_SYN_RECV &&
			     sk->sk_state != TCP_FIN_WAIT1);
		tcp_fastopen_synack_timer(sk);
		/* Before we receive ACK to our SYN-ACK don't retransmit
		 * anything else (e.g., data or FIN segments).
		 */
		return;
	}

    /* 如果没有数据包在网络中，则直接退出 */
	if (!tp->packets_out)
		goto out;

	WARN_ON(tcp_write_queue_empty(sk));

	tp->tlp_high_seq = 0;   /* TLP失败了，将TLP对应的标记清零 */

	if (!tp->snd_wnd &&     /* 发送窗口被减小为0 */
        !sock_flag(sk, SOCK_DEAD) &&    /*  TODO: 这是什么意思？ */
	    !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {     /* socket不是处于SYN_SENT或SYN_RECV阶段 */
		/* Receiver dastardly shrinks window. Our retransmits
		 * become zero probes, but we should not timeout this
		 * connection. If the socket is an orphan, time it out,
		 * we cannot allow such beasts to hang infinitely.
		 */
		struct inet_sock *inet = inet_sk(sk);
        /* 打印相关的警告信息 */
		if (sk->sk_family == AF_INET) {
			LIMIT_NETDEBUG(KERN_DEBUG pr_fmt("Peer %pI4:%u/%u unexpectedly shrunk window %u:%u (repaired)\n"),
				       &inet->inet_daddr,
				       ntohs(inet->inet_dport), inet->inet_num,
				       tp->snd_una, tp->snd_nxt);
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (sk->sk_family == AF_INET6) {
			struct ipv6_pinfo *np = inet6_sk(sk);
			LIMIT_NETDEBUG(KERN_DEBUG pr_fmt("Peer %pI6:%u/%u unexpectedly shrunk window %u:%u (repaired)\n"),
				       &np->daddr,
				       ntohs(inet->inet_dport), inet->inet_num,
				       tp->snd_una, tp->snd_nxt);
		}
#endif
        /* 如果TCP_RTO_MAX时间内还未收到任何ACK，则调用tcp_write_err()->tcp_done()关闭socket */
		if (tcp_time_stamp - tp->rcv_tstamp > TCP_RTO_MAX) {
			tcp_write_err(sk);
			goto out;
		}
		tcp_enter_loss(sk, 0);  /* 进入TCP_CA_Loss阶段 */
        /* 重传队首的一个skb */
		tcp_retransmit_skb(sk, tcp_write_queue_head(sk));
        /* 清除路由 */
		__sk_dst_reset(sk);
		goto out_reset_timer;
	}

    /* 如果已经尝试重传了够长时间还没用，则是时候放弃了 */
	if (tcp_write_timeout(sk))
		goto out;

    /* 如果是第一次RTO重传，则根据情况来调整计数器 */
	if (icsk->icsk_retransmits == 0) {
		int mib_idx;

		if (icsk->icsk_ca_state == TCP_CA_Recovery) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKRECOVERYFAIL;
			else
				mib_idx = LINUX_MIB_TCPRENORECOVERYFAIL;
		} else if (icsk->icsk_ca_state == TCP_CA_Loss) {
			mib_idx = LINUX_MIB_TCPLOSSFAILURES;
		} else if ((icsk->icsk_ca_state == TCP_CA_Disorder) ||
			   tp->sacked_out) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKFAILURES;
			else
				mib_idx = LINUX_MIB_TCPRENOFAILURES;
		} else {
			mib_idx = LINUX_MIB_TCPTIMEOUTS;
		}
		NET_INC_STATS_BH(sock_net(sk), mib_idx);
	}

    /* 正常方式进入重传状态, 不正常方式指的是前面发现对端shrunk receive window的情况 */
    /* 这里的参数0，表示依然保留SACK信息，毕竟没有任何证明对端违背SACK信息的证据 */
	tcp_enter_loss(sk, 0);

	if (tcp_retransmit_skb(sk, tcp_write_queue_head(sk)) > 0) {
		/* Retransmission failed because of local congestion,
		 * do not backoff.
		 */
		if (!icsk->icsk_retransmits)
			icsk->icsk_retransmits = 1;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					  min(icsk->icsk_rto, TCP_RESOURCE_PROBE_INTERVAL),
					  TCP_RTO_MAX);
		goto out;
	}

	/* Increase the timeout each time we retransmit.  Note that
	 * we do not increase the rtt estimate.  rto is initialized
	 * from rtt, but increases here.  Jacobson (SIGCOMM 88) suggests
	 * that doubling rto each time is the least we can get away with.
	 * In KA9Q, Karn uses this for the first few times, and then
	 * goes to quadratic.  netBSD doubles, but only goes up to *64,
	 * and clamps at 1 to 64 sec afterwards.  Note that 120 sec is
	 * defined in the protocol as the maximum possible RTT.  I guess
	 * we'll have to use something other than TCP to talk to the
	 * University of Mars.
	 *
	 * PAWS allows us longer timeouts and large windows, so once
	 * implemented ftp to mars will work nicely. We will have to fix
	 * the 120 second clamps though!
	 */
	icsk->icsk_backoff++;
	icsk->icsk_retransmits++;

out_reset_timer:
	/* If stream is thin, use linear timeouts. Since 'icsk_backoff' is
	 * used to reset timer, set to 0. Recalculate 'icsk_rto' as this
	 * might be increased if the stream oscillates between thin and thick,
	 * thus the old value might already be too high compared to the value
	 * set by 'tcp_set_rto' in tcp_input.c which resets the rto without
	 * backoff. Limit to TCP_THIN_LINEAR_RETRIES before initiating
	 * exponential backoff behaviour to avoid continue hammering
	 * linear-timeout retransmissions into a black hole
	 */
	if (sk->sk_state == TCP_ESTABLISHED &&
	    (tp->thin_lto || sysctl_tcp_thin_linear_timeouts) &&
	    tcp_stream_is_thin(tp) &&
	    icsk->icsk_retransmits <= TCP_THIN_LINEAR_RETRIES) {
		icsk->icsk_backoff = 0;
		icsk->icsk_rto = min(__tcp_set_rto(tp), TCP_RTO_MAX);
	} else {
		/* Use normal (exponential) backoff */
		icsk->icsk_rto = min(icsk->icsk_rto << 1, TCP_RTO_MAX);
	}
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS, icsk->icsk_rto, TCP_RTO_MAX);
	if (retransmits_timed_out(sk, sysctl_tcp_retries1 + 1, 0, 0))
		__sk_dst_reset(sk);

out:;
}

void tcp_write_timer_handler(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int event;

    /* 如果socket已经关闭，或者没有启用定时器，则直接返回 */
	if (sk->sk_state == TCP_CLOSE || !icsk->icsk_pending)
		goto out;

    /* 如果还没有到超时时刻，则重设定时器继续计时 */
	if (time_after(icsk->icsk_timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
		goto out;
	}

    /* 可以看出，重传定时器使用icsk->icsk_pending这个变量来进一步区分具体的重传定时器 */
	event = icsk->icsk_pending;

	switch (event) {
	case ICSK_TIME_EARLY_RETRANS:
        /* early retransmit是用来解决某些特定场景下，没有足够dupack触发fast retransmit的造成的问题。 
         * 本质是通过检测出特定场景，然后降低dupack threshold来触发fast retransmit */
		tcp_resume_early_retransmit(sk);
		break;
	case ICSK_TIME_LOSS_PROBE:          
        /* 如果是Probe Timeout 定时器超时，则发送一个Tail Loss Probe(TLP)包 */
		tcp_send_loss_probe(sk);
		break;
	case ICSK_TIME_RETRANS:
		icsk->icsk_pending = 0;
        /* 如果是RTO定时器超时，则进入LOSS状态 */
		tcp_retransmit_timer(sk);
		break;
	case ICSK_TIME_PROBE0:
		icsk->icsk_pending = 0;
		tcp_probe_timer(sk);
		break;
	}

out:
	sk_mem_reclaim(sk);
}

static void tcp_write_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
        /* 如果此时socket没有被user占用，则调用实际的处理函数 */
		tcp_write_timer_handler(sk);
	} else {
		/* deleguate our work to tcp_release_cb() */
		if (!test_and_set_bit(TCP_WRITE_TIMER_DEFERRED, &tcp_sk(sk)->tsq_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 *	Timer for listening sockets
 */

static void tcp_synack_timer(struct sock *sk)
{
	inet_csk_reqsk_queue_prune(sk, TCP_SYNQ_INTERVAL,
				   TCP_TIMEOUT_INIT, TCP_RTO_MAX);
}

void tcp_syn_ack_timeout(struct sock *sk, struct request_sock *req)
{
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPTIMEOUTS);
}
EXPORT_SYMBOL(tcp_syn_ack_timeout);

void tcp_set_keepalive(struct sock *sk, int val)
{
	if ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))
		return;

	if (val && !sock_flag(sk, SOCK_KEEPOPEN))
		inet_csk_reset_keepalive_timer(sk, keepalive_time_when(tcp_sk(sk)));
	else if (!val)
		inet_csk_delete_keepalive_timer(sk);
}


static void tcp_keepalive_timer (unsigned long data)
{
	struct sock *sk = (struct sock *) data;
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 elapsed;

	/* Only process if socket is not in use. */
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Try again later. */
		inet_csk_reset_keepalive_timer (sk, HZ/20);
		goto out;
	}

	if (sk->sk_state == TCP_LISTEN) {
		tcp_synack_timer(sk);
		goto out;
	}

	if (sk->sk_state == TCP_FIN_WAIT2 && sock_flag(sk, SOCK_DEAD)) {
		if (tp->linger2 >= 0) {
			const int tmo = tcp_fin_time(sk) - TCP_TIMEWAIT_LEN;

			if (tmo > 0) {
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
		tcp_send_active_reset(sk, GFP_ATOMIC);
		goto death;
	}

	if (!sock_flag(sk, SOCK_KEEPOPEN) || sk->sk_state == TCP_CLOSE)
		goto out;

	elapsed = keepalive_time_when(tp);

	/* It is alive without keepalive 8) */
	if (tp->packets_out || tcp_send_head(sk))
		goto resched;

	elapsed = keepalive_time_elapsed(tp);

	if (elapsed >= keepalive_time_when(tp)) {
		/* If the TCP_USER_TIMEOUT option is enabled, use that
		 * to determine when to timeout instead.
		 */
		if ((icsk->icsk_user_timeout != 0 &&
		    elapsed >= icsk->icsk_user_timeout &&
		    icsk->icsk_probes_out > 0) ||
		    (icsk->icsk_user_timeout == 0 &&
		    icsk->icsk_probes_out >= keepalive_probes(tp))) {
			tcp_send_active_reset(sk, GFP_ATOMIC);
			tcp_write_err(sk);
			goto out;
		}
		if (tcp_write_wakeup(sk) <= 0) {
			icsk->icsk_probes_out++;
			elapsed = keepalive_intvl_when(tp);
		} else {
			/* If keepalive was lost due to local congestion,
			 * try harder.
			 */
			elapsed = TCP_RESOURCE_PROBE_INTERVAL;
		}
	} else {
		/* It is tp->rcv_tstamp + keepalive_time_when(tp) */
		elapsed = keepalive_time_when(tp) - elapsed;
	}

	sk_mem_reclaim(sk);

resched:
	inet_csk_reset_keepalive_timer (sk, elapsed);
	goto out;

death:
	tcp_done(sk);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/* 初始化TCP的三大定时器 */
void tcp_init_xmit_timers(struct sock *sk)
{
    /* 设置重传定时器的处理函数为tcp_write_timer */
    /* 设置延迟确认定时器的处理函数为tcp_delack_timer */
    /* 设置保活定时器的处理函数为tcp_keepalive_timer */
	inet_csk_init_xmit_timers(sk, &tcp_write_timer, &tcp_delack_timer,
				  &tcp_keepalive_timer);
}
EXPORT_SYMBOL(tcp_init_xmit_timers);
