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

/*
 * Changes:	Pedro Roque	:	Retransmit queue handled by TCP.
 *				:	Fragmentation on mtu decrease
 *				:	Segment collapse on retransmit
 *				:	AF independence
 *
 *		Linus Torvalds	:	send_delayed_ack
 *		David S. Miller	:	Charge memory using the right skb
 *					during syn/ack processing.
 *		David S. Miller :	Output engine completely rewritten.
 *		Andrea Arcangeli:	SYNACK carry ts_recent in tsecr.
 *		Cacophonix Gaul :	draft-minshall-nagle-01
 *		J Hadi Salim	:	ECN support
 *
 */

#define pr_fmt(fmt) "TCP: " fmt

#include <net/tcp.h>

#include <linux/compiler.h>
#include <linux/gfp.h>
#include <linux/module.h>

/* People can turn this off for buggy TCP's found in printers etc. */
int sysctl_tcp_retrans_collapse __read_mostly = 1;

/* People can turn this on to work with those rare, broken TCPs that
 * interpret the window field as a signed quantity.
 */
int sysctl_tcp_workaround_signed_windows __read_mostly = 0;

/* Default TSQ limit of two TSO segments */
/* 一个TSO segment的最大值为GSO_MAX_SIZE, 等于64KB。 
 * TSQ机制默认限制的字节数等于两个最大的TSO段 */
int sysctl_tcp_limit_output_bytes __read_mostly = 131072;

/* This limits the percentage of the congestion window which we
 * will allow a single TSO frame to consume.  Building TSO frames
 * which are too large can cause TCP streams to be bursty.
 */
int sysctl_tcp_tso_win_divisor __read_mostly = 3;

int sysctl_tcp_mtu_probing __read_mostly = 0;
int sysctl_tcp_base_mss __read_mostly = TCP_BASE_MSS;

/* By default, RFC2861 behavior.  */
int sysctl_tcp_slow_start_after_idle __read_mostly = 1;

static bool tcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
			   int push_one, gfp_t gfp);

/* Account for new data that has been sent to the network. */
static void tcp_event_new_data_sent(struct sock *sk, const struct sk_buff *skb)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int prior_packets = tp->packets_out;

    /* 更新send_head、snd_nxt、packets_out */
	tcp_advance_send_head(sk, skb);
	tp->snd_nxt = TCP_SKB_CB(skb)->end_seq;

    /* 更新已经发出去，但未被确认的数据包数目 */
	tp->packets_out += tcp_skb_pcount(skb);
	if (!prior_packets ||   /* 如果之前未发送过数据，或者之前所有数据已经被按序确认掉了，那么应该开始RTO timer计时 */
        /* 如果之前设置了ER timer，或者TLP timer，都是因为没有新数据发送才会设置的，如果一旦有新数据发送，这两个timer应该被取消，换回RTO timer */
        icsk->icsk_pending == ICSK_TIME_EARLY_RETRANS ||
	    icsk->icsk_pending == ICSK_TIME_LOSS_PROBE) {
		tcp_rearm_rto(sk);
	}
}

/* SND.NXT, if window was not shrunk.
 * If window has been shrunk, what should we make? It is not clear at all.
 * Using SND.UNA we will fail to open window, SND.NXT is out of window. :-(
 * Anything in between SND.UNA...SND.UNA+SND.WND also can be already
 * invalid. OK, let's make this for now:
 */
/* 返回一个合法的seq number值作为发送数据包的seq number */
/* 目前该函数仅在发送reset包和纯ACK包时使用 */
static inline __u32 tcp_acceptable_seq(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

    /* 一般情况下，这个seq值就是snd_nxt */
	if (!before(tcp_wnd_end(tp), tp->snd_nxt))
		return tp->snd_nxt;
    /* 但如果对端window缩小，为了保证数据包序号处于对端的可接受范围，
     * 只好强制使用tcp_wnd_end(tp)作为seq number */
	else
		return tcp_wnd_end(tp);
}

/* Calculate mss to advertise in SYN segment.
 * RFC1122, RFC1063, draft-ietf-tcpimpl-pmtud-01 state that:
 *
 * 1. It is independent of path mtu.
 * 2. Ideally, it is maximal possible segment size i.e. 65535-40.
 * 3. For IPv4 it is reasonable to calculate it from maximal MTU of
 *    attached devices, because some buggy hosts are confused by
 *    large MSS.
 * 4. We do not make 3, we advertise MSS, calculated from first
 *    hop device mtu, but allow to raise it to ip_rt_min_advmss.
 *    This may be overridden via information stored in routing table.
 * 5. Value 65535 for MSS is valid in IPv6 and means "as large as possible,
 *    probably even Jumbo".
 */
/* 计算出放在SYN包中的MSS选项值 */
static __u16 tcp_advertise_mss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct dst_entry *dst = __sk_dst_get(sk);
	int mss = tp->advmss;

	if (dst) {
		unsigned int metric = dst_metric_advmss(dst);

		if (metric < mss) {
			mss = metric;
			tp->advmss = mss;
		}
	}

	return (__u16)mss;
}

/* RFC2861. Reset CWND after idle period longer RTO to "restart window".
 * This is the first part of cwnd validation mechanism. */
static void tcp_cwnd_restart(struct sock *sk, const struct dst_entry *dst)
{
	struct tcp_sock *tp = tcp_sk(sk);
	s32 delta = tcp_time_stamp - tp->lsndtime;
	u32 restart_cwnd = tcp_init_cwnd(tp, dst);
	u32 cwnd = tp->snd_cwnd;

	tcp_ca_event(sk, CA_EVENT_CWND_RESTART);

	tp->snd_ssthresh = tcp_current_ssthresh(sk);
	restart_cwnd = min(restart_cwnd, cwnd);

	while ((delta -= inet_csk(sk)->icsk_rto) > 0 && cwnd > restart_cwnd)
		cwnd >>= 1;
	tp->snd_cwnd = max(cwnd, restart_cwnd);
	tp->snd_cwnd_stamp = tcp_time_stamp;
	tp->snd_cwnd_used = 0;
}

/* Congestion state accounting after a packet has been sent. */
static void tcp_event_data_sent(struct tcp_sock *tp,
				struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const u32 now = tcp_time_stamp;

	if (sysctl_tcp_slow_start_after_idle &&
	    (!tp->packets_out && (s32)(now - tp->lsndtime) > icsk->icsk_rto))
		tcp_cwnd_restart(sk, __sk_dst_get(sk));

	tp->lsndtime = now;     /* 更新最近一次发送数据的时间 */

	/* If it is a reply for ato after last received
	 * packet, enter pingpong mode.
	 */
    /* 如果这次发送数据距离上次收到数据的间隔在ato(Ack TimeOut)时间内，
     * 则进入pingpong模式，即interactive -- 数据有来有往的情况 */
	if ((u32)(now - icsk->icsk_ack.lrcvtime) < icsk->icsk_ack.ato)
		icsk->icsk_ack.pingpong = 1;
}

/* Account for an ACK we sent. */
static inline void tcp_event_ack_sent(struct sock *sk, unsigned int pkts)
{
    /* 发出了pkts个ack包，就减小pkts个需要被快速确认的ACK个数 */
	tcp_dec_quickack_mode(sk, pkts);
    /* 当发送出一个ACK后，就清除延迟确认定时器 */
	inet_csk_clear_xmit_timer(sk, ICSK_TIME_DACK);
}

/* Determine a window scaling and initial window to offer.
 * Based on the assumption that the given amount of space
 * will be offered. Store the results in the tp structure.
 * NOTE: for smooth operation initial space offering should
 * be a multiple of mss if possible. We assume here that mss >= 1.
 * This MUST be enforced by all callers.
 */
void tcp_select_initial_window(int __space, __u32 mss,
			       __u32 *rcv_wnd, __u32 *window_clamp,
			       int wscale_ok, __u8 *rcv_wscale,
			       __u32 init_rcv_wnd)
{
	unsigned int space = (__space < 0 ? 0 : __space);

	/* If no clamp set the clamp to the max possible scaled window */
	if (*window_clamp == 0)
		(*window_clamp) = (65535 << 14);
	space = min(*window_clamp, space);

	/* Quantize space offering to a multiple of mss if possible. */
	if (space > mss)
		space = (space / mss) * mss;

	/* NOTE: offering an initial window larger than 32767
	 * will break some buggy TCP stacks. If the admin tells us
	 * it is likely we could be speaking with such a buggy stack
	 * we will truncate our initial window offering to 32K-1
	 * unless the remote has sent us a window scaling option,
	 * which we interpret as a sign the remote TCP is not
	 * misinterpreting the window field as a signed quantity.
	 */
	if (sysctl_tcp_workaround_signed_windows)
		(*rcv_wnd) = min(space, MAX_TCP_WINDOW);
	else
		(*rcv_wnd) = space;

	(*rcv_wscale) = 0;
	if (wscale_ok) {
		/* Set window scaling on max possible window
		 * See RFC1323 for an explanation of the limit to 14
		 */
		space = max_t(u32, sysctl_tcp_rmem[2], sysctl_rmem_max);
		space = min_t(u32, space, *window_clamp);
		while (space > 65535 && (*rcv_wscale) < 14) {
			space >>= 1;
			(*rcv_wscale)++;
		}
	}

	/* Set initial window to a value enough for senders starting with
	 * initial congestion window of TCP_DEFAULT_INIT_RCVWND. Place
	 * a limit on the initial window when mss is larger than 1460.
	 */
	if (mss > (1 << *rcv_wscale)) {
		int init_cwnd = TCP_DEFAULT_INIT_RCVWND;
		if (mss > 1460)
			init_cwnd =
			max_t(u32, (1460 * TCP_DEFAULT_INIT_RCVWND) / mss, 2);
		/* when initializing use the value from init_rcv_wnd
		 * rather than the default from above
		 */
		if (init_rcv_wnd)
			*rcv_wnd = min(*rcv_wnd, init_rcv_wnd * mss);
		else
			*rcv_wnd = min(*rcv_wnd, init_cwnd * mss);
	}

	/* Set the clamp no higher than max representable value */
	(*window_clamp) = min(65535U << (*rcv_wscale), *window_clamp);
}
EXPORT_SYMBOL(tcp_select_initial_window);

/* Chose a new window to advertise, update state in tcp_sock for the
 * socket, and return result with RFC1323 scaling applied.  The return
 * value can be stuffed directly into th->window for an outgoing
 * frame.
 */
/* TODO: 确定接收窗口如是如何计算出来的 */
static u16 tcp_select_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 cur_win = tcp_receive_window(tp);
	u32 new_win = __tcp_select_window(sk);

	/* Never shrink the offered window */
	if (new_win < cur_win) {
		/* Danger Will Robinson!
		 * Don't update rcv_wup/rcv_wnd here or else
		 * we will not be able to advertise a zero
		 * window in time.  --DaveM
		 *
		 * Relax Will Robinson.
		 */
		new_win = ALIGN(cur_win, 1 << tp->rx_opt.rcv_wscale);
	}
	tp->rcv_wnd = new_win;
	tp->rcv_wup = tp->rcv_nxt;      /* see, rcv_wup此时与rcv_nxt进行同步 */

	/* Make sure we do not exceed the maximum possible
	 * scaled window.
	 */
	if (!tp->rx_opt.rcv_wscale && sysctl_tcp_workaround_signed_windows)
		new_win = min(new_win, MAX_TCP_WINDOW);
	else
		new_win = min(new_win, (65535U << tp->rx_opt.rcv_wscale));

	/* RFC1323 scaling applied */
	new_win >>= tp->rx_opt.rcv_wscale;

	/* If we advertise zero window, disable fast path. */
	if (new_win == 0)
		tp->pred_flags = 0;

	return new_win;
}

/* Packet ECN state for a SYN-ACK */
static inline void TCP_ECN_send_synack(const struct tcp_sock *tp, struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_CWR;
	if (!(tp->ecn_flags & TCP_ECN_OK))
		TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_ECE;
}

/* Packet ECN state for a SYN.  */
/* 在syn包的TCP头部，设置ECN、CWR标记，表示支持ECN
 * 默认不开启 */
static inline void TCP_ECN_send_syn(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->ecn_flags = 0;
    /* 需要选项被开启
     * 默认值为2， 表示仅对于被动建联的请求开启ECN标记，主动建联时不设置ECN标记 */
	if (sock_net(sk)->ipv4.sysctl_tcp_ecn == 1) {
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_ECE | TCPHDR_CWR;
		tp->ecn_flags = TCP_ECN_OK;
	}
}

static __inline__ void
TCP_ECN_make_synack(const struct request_sock *req, struct tcphdr *th)
{
	if (inet_rsk(req)->ecn_ok)
		th->ece = 1;
}

/* Set up ECN state for a packet on a ESTABLISHED socket that is about to
 * be sent.
 */
/* 对一个普通的数据包设置ECN标记 */
static inline void TCP_ECN_send(struct sock *sk, struct sk_buff *skb,
				int tcp_header_len)
{
	struct tcp_sock *tp = tcp_sk(sk);

    /* 必须本地支持ECN才会设置 */
	if (tp->ecn_flags & TCP_ECN_OK) {
		/* Not-retransmitted data segment: set ECT and inject CWR. */
		if (skb->len != tcp_header_len &&   /* skb有数据，且不是重传包 */
		    !before(TCP_SKB_CB(skb)->seq, tp->snd_nxt)) {

			INET_ECN_xmit(sk);  /* 设置tos的ecn域，表示支持 */
            /* 发送端已经收到拥塞信号 */
			if (tp->ecn_flags & TCP_ECN_QUEUE_CWR) {
				tp->ecn_flags &= ~TCP_ECN_QUEUE_CWR;
				tcp_hdr(skb)->cwr = 1;  /* 设置包头的CWR域，通知对端已经收到了ECN拥塞信号 */
				skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;   /* 标记skb，设置了CWR域 */
			}
		} else {
			/* ACK or retransmitted segment: clear ECT|CE */
			INET_ECN_dontxmit(sk);
		}
        /* 作为接收端，要通知发送端, ece表示 ecn echo */
		if (tp->ecn_flags & TCP_ECN_DEMAND_CWR)
			tcp_hdr(skb)->ece = 1;
	}
}

/* Constructs common control bits of non-data skb. If SYN/FIN is present,
 * auto increment end seqno.
 */
/* 初始化一个不携带数据的skb */
static void tcp_init_nondata_skb(struct sk_buff *skb, u32 seq, u8 flags)
{
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum = 0;

	TCP_SKB_CB(skb)->tcp_flags = flags;
	TCP_SKB_CB(skb)->sacked = 0;

	skb_shinfo(skb)->gso_segs = 1;
	skb_shinfo(skb)->gso_size = 0;
	skb_shinfo(skb)->gso_type = 0;

    /* 不包含数据的skb的end_seq自然应该是等于seq的，但如果要携带SYN或者FIN标记，
     * 则end_seq序号增加1. 也就是说SYN和FIN是会占用tcp 序号的 */
	TCP_SKB_CB(skb)->seq = seq;
	if (flags & (TCPHDR_SYN | TCPHDR_FIN))
		seq++;
	TCP_SKB_CB(skb)->end_seq = seq;
}

/* 如果snd_up不等于snd_una，则说明有urgent data需要发送 */
static inline bool tcp_urg_mode(const struct tcp_sock *tp)
{
	return tp->snd_una != tp->snd_up;
}

#define OPTION_SACK_ADVERTISE	(1 << 0)
#define OPTION_TS		(1 << 1)
#define OPTION_MD5		(1 << 2)
#define OPTION_WSCALE		(1 << 3)
#define OPTION_FAST_OPEN_COOKIE	(1 << 8)

struct tcp_out_options {
	u16 options;		/* bit field of OPTION_* */ /* 标记开启了哪些option */
	u16 mss;		/* 0 to disable */
	u8 ws;			/* window scale, 0 to disable */
	u8 num_sack_blocks;	/* number of SACK blocks to include */
	u8 hash_size;		/* bytes in hash_location */
	__u8 *hash_location;	/* temporary pointer, overloaded */
	__u32 tsval, tsecr;	/* need to include OPTION_TS */
	struct tcp_fastopen_cookie *fastopen_cookie;	/* Fast open cookie */
};

/* Write previously computed TCP options to the packet.
 *
 * Beware: Something in the Internet is very sensitive to the ordering of
 * TCP options, we learned this through the hard way, so be careful here.
 * Luckily we can at least blame others for their non-compliance but from
 * inter-operatibility perspective it seems that we're somewhat stuck with
 * the ordering which we have been using if we want to keep working with
 * those broken things (not that it currently hurts anybody as there isn't
 * particular reason why the ordering would need to be changed).
 *
 * At least SACK_PERM as the first option is known to lead to a disaster
 * (but it may well be that other scenarios fail similarly).
 */
/* 实际往skb数据包头部填充选项 */
/* option format的基本格式：
 *      1字节 option kind + 1字节 option len + (option len - 2)字节 option data
 * 如果有的选项长度不是4字节的整数倍，则要添加TCPOPT_NOP空类型选项进行对齐处理
 * 比如timestamp选项时10字节长度，它的做法是添加两个TCPOPT_NOP选项在头部 */
static void tcp_options_write(__be32 *ptr, struct tcp_sock *tp,
			      struct tcp_out_options *opts)
{
	u16 options = opts->options;	/* mungable copy */

    /* MD5选项 */
	if (unlikely(OPTION_MD5 & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
			       (TCPOPT_MD5SIG << 8) | TCPOLEN_MD5SIG);
		/* overload cookie hash location */
		opts->hash_location = (__u8 *)ptr;
		ptr += 4;
	}

    /* 只有SYN包中会有mss */
	if (unlikely(opts->mss)) {
		*ptr++ = htonl((TCPOPT_MSS << 24) |
			       (TCPOLEN_MSS << 16) |
			       opts->mss);
	}

	if (likely(OPTION_TS & options)) {
        /* 如果开启了timestamp，那么就利用它的空白区域写入SACK_Permitted选项内容 */
		if (unlikely(OPTION_SACK_ADVERTISE & options)) {
			*ptr++ = htonl((TCPOPT_SACK_PERM << 24) |
				       (TCPOLEN_SACK_PERM << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
			options &= ~OPTION_SACK_ADVERTISE;
		} else {
			*ptr++ = htonl((TCPOPT_NOP << 24) |
				       (TCPOPT_NOP << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
		}
		*ptr++ = htonl(opts->tsval);
		*ptr++ = htonl(opts->tsecr);
	}

    /* 如果没有开启timestamp选项，写入SACK_Permitted选项内容 */
	if (unlikely(OPTION_SACK_ADVERTISE & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_SACK_PERM << 8) |
			       TCPOLEN_SACK_PERM);
	}

    /* 只有SYN包中带win scale选项，所以是unlikely */
	if (unlikely(OPTION_WSCALE & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_WINDOW << 16) |
			       (TCPOLEN_WINDOW << 8) |
			       opts->ws);
	}

    /* 写入SACK选项内容 */
	if (unlikely(opts->num_sack_blocks)) {
        /* 具体SACK选项每个block需要写的内容，已经事先写入了tp结构体中 */
		struct tcp_sack_block *sp = tp->rx_opt.dsack ?
			tp->duplicate_sack : tp->selective_acks;
		int this_sack;

		*ptr++ = htonl((TCPOPT_NOP  << 24) |
			       (TCPOPT_NOP  << 16) |
			       (TCPOPT_SACK <<  8) |
			       (TCPOLEN_SACK_BASE + (opts->num_sack_blocks *
						     TCPOLEN_SACK_PERBLOCK)));

		for (this_sack = 0; this_sack < opts->num_sack_blocks;
		     ++this_sack) {
			*ptr++ = htonl(sp[this_sack].start_seq);
			*ptr++ = htonl(sp[this_sack].end_seq);
		}

        /* dsack只会发送一次 */
		tp->rx_opt.dsack = 0;
	}

    /* 写入fastopen选项 */
	if (unlikely(OPTION_FAST_OPEN_COOKIE & options)) {
		struct tcp_fastopen_cookie *foc = opts->fastopen_cookie;

		*ptr++ = htonl((TCPOPT_EXP << 24) |
			       ((TCPOLEN_EXP_FASTOPEN_BASE + foc->len) << 16) |
			       TCPOPT_FASTOPEN_MAGIC);

		memcpy(ptr, foc->val, foc->len);
		if ((foc->len & 3) == 2) {
			u8 *align = ((u8 *)ptr) + foc->len;
			align[0] = align[1] = TCPOPT_NOP;
		}
		ptr += (foc->len + 3) >> 2;
	}
}

/* Compute TCP options for SYN packets. This is not the final
 * network wire format yet.
 */
/* 计算SYN包的option */
static unsigned int tcp_syn_options(struct sock *sk, struct sk_buff *skb,
				struct tcp_out_options *opts,
				struct tcp_md5sig_key **md5)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int remaining = MAX_TCP_OPTION_SPACE;  /* 最大长度:40B */
	struct tcp_fastopen_request *fastopen = tp->fastopen_req;

#ifdef CONFIG_TCP_MD5SIG
	*md5 = tp->af_specific->md5_lookup(sk, sk);
	if (*md5) {
		opts->options |= OPTION_MD5;
		remaining -= TCPOLEN_MD5SIG_ALIGNED;
	}
#else
	*md5 = NULL;
#endif

	/* We always get an MSS option.  The option bytes which will be seen in
	 * normal data packets should timestamps be used, must be in the MSS
	 * advertised.  But we subtract them from tp->mss_cache so that
	 * calculations in tcp_sendmsg are simpler etc.  So account for this
	 * fact here if necessary.  If we don't do this correctly, as a
	 * receiver we won't recognize data packets as being full sized when we
	 * should, and thus we won't abide by the delayed ACK rules correctly.
	 * SACKs don't matter, we never delay an ACK when we have any of those
	 * going out.  */
	opts->mss = tcp_advertise_mss(sk);
	remaining -= TCPOLEN_MSS_ALIGNED;

    /* 从代码上都是偏向开启的以下选项的：timestamp、window scaling、sack */
	if (likely(sysctl_tcp_timestamps && *md5 == NULL)) {
		opts->options |= OPTION_TS;
		opts->tsval = TCP_SKB_CB(skb)->when + tp->tsoffset;
		opts->tsecr = tp->rx_opt.ts_recent;
		remaining -= TCPOLEN_TSTAMP_ALIGNED;
	}
    /* window scaling 只在SYN包中有效，谨记 */
	if (likely(sysctl_tcp_window_scaling)) {
		opts->ws = tp->rx_opt.rcv_wscale;
		opts->options |= OPTION_WSCALE;
		remaining -= TCPOLEN_WSCALE_ALIGNED;
	}
	if (likely(sysctl_tcp_sack)) {
		opts->options |= OPTION_SACK_ADVERTISE;
		if (unlikely(!(OPTION_TS & opts->options)))
			remaining -= TCPOLEN_SACKPERM_ALIGNED;
	}

	if (fastopen && fastopen->cookie.len >= 0) {
		u32 need = TCPOLEN_EXP_FASTOPEN_BASE + fastopen->cookie.len;
		need = (need + 3) & ~3U;  /* Align to 32 bits */
		if (remaining >= need) {
			opts->options |= OPTION_FAST_OPEN_COOKIE;
			opts->fastopen_cookie = &fastopen->cookie;
			remaining -= need;
			tp->syn_fastopen = 1;
		}
	}

    /* 返回值是用掉了多少空间 */
	return MAX_TCP_OPTION_SPACE - remaining;
}

/* Set up TCP options for SYN-ACKs. */
/* 设置好SYN/ACK包的选项 */
static unsigned int tcp_synack_options(struct sock *sk,
				   struct request_sock *req,
				   unsigned int mss, struct sk_buff *skb,
				   struct tcp_out_options *opts,
				   struct tcp_md5sig_key **md5,
				   struct tcp_fastopen_cookie *foc)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	unsigned int remaining = MAX_TCP_OPTION_SPACE;

#ifdef CONFIG_TCP_MD5SIG
	*md5 = tcp_rsk(req)->af_specific->md5_lookup(sk, req);
	if (*md5) {
		opts->options |= OPTION_MD5;
		remaining -= TCPOLEN_MD5SIG_ALIGNED;

		/* We can't fit any SACK blocks in a packet with MD5 + TS
		 * options. There was discussion about disabling SACK
		 * rather than TS in order to fit in better with old,
		 * buggy kernels, but that was deemed to be unnecessary.
		 */
		ireq->tstamp_ok &= !ireq->sack_ok;
	}
#else
	*md5 = NULL;
#endif

	/* We always send an MSS option. */
    /* MSS是必须的 */
	opts->mss = mss;
	remaining -= TCPOLEN_MSS_ALIGNED;

    /* win scale必须是双向协商，同时使用的 */
	if (likely(ireq->wscale_ok)) {
		opts->ws = ireq->rcv_wscale;
		opts->options |= OPTION_WSCALE;
		remaining -= TCPOLEN_WSCALE_ALIGNED;
	}
    /* tstamp也必须是双向同时支持的 */
	if (likely(ireq->tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = TCP_SKB_CB(skb)->when;
		opts->tsecr = req->ts_recent;
		remaining -= TCPOLEN_TSTAMP_ALIGNED;
	}
    /* 只要对端支持SACK，打上标记 */
	if (likely(ireq->sack_ok)) {
		opts->options |= OPTION_SACK_ADVERTISE;
		if (unlikely(!ireq->tstamp_ok))
			remaining -= TCPOLEN_SACKPERM_ALIGNED;
	}
    /* TODO: 需要系统的看一下fastopen的实现 */
	if (foc != NULL) {
		u32 need = TCPOLEN_EXP_FASTOPEN_BASE + foc->len;
		need = (need + 3) & ~3U;  /* Align to 32 bits */
		if (remaining >= need) {
			opts->options |= OPTION_FAST_OPEN_COOKIE;
			opts->fastopen_cookie = foc;
			remaining -= need;
		}
	}

	return MAX_TCP_OPTION_SPACE - remaining;
}

/* Compute TCP options for ESTABLISHED sockets. This is not the
 * final wire format yet.
 */
/* 计算除SYN包、SYN/ACK包之外的数据包的选项 */
static unsigned int tcp_established_options(struct sock *sk, struct sk_buff *skb,
					struct tcp_out_options *opts,
					struct tcp_md5sig_key **md5)
{
	struct tcp_skb_cb *tcb = skb ? TCP_SKB_CB(skb) : NULL;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int size = 0;
	unsigned int eff_sacks;

#ifdef CONFIG_TCP_MD5SIG
	*md5 = tp->af_specific->md5_lookup(sk, sk);
	if (unlikely(*md5)) {
		opts->options |= OPTION_MD5;
		size += TCPOLEN_MD5SIG_ALIGNED;
	}
#else
	*md5 = NULL;
#endif

    /* 处理timestamp选项 */
	if (likely(tp->rx_opt.tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = tcb ? tcb->when + tp->tsoffset : 0;
		opts->tsecr = tp->rx_opt.ts_recent;
		size += TCPOLEN_TSTAMP_ALIGNED;
	}

    /* 处理SACK和DSACK选项 */
	eff_sacks = tp->rx_opt.num_sacks + tp->rx_opt.dsack;
	if (unlikely(eff_sacks)) {
		const unsigned int remaining = MAX_TCP_OPTION_SPACE - size;
		opts->num_sack_blocks =
			min_t(unsigned int, eff_sacks,
			      (remaining - TCPOLEN_SACK_BASE_ALIGNED) /
			      TCPOLEN_SACK_PERBLOCK);
		size += TCPOLEN_SACK_BASE_ALIGNED +
			opts->num_sack_blocks * TCPOLEN_SACK_PERBLOCK;
	}

	return size;
}


/* TCP SMALL QUEUES (TSQ)
 *
 * TSQ goal is to keep small amount of skbs per tcp flow in tx queues (qdisc+dev)
 * to reduce RTT and bufferbloat.
 * We do this using a special skb destructor (tcp_wfree).
 *
 * Its important tcp_wfree() can be replaced by sock_wfree() in the event skb
 * needs to be reallocated in a driver.
 * The invariant being skb->truesize substracted from sk->sk_wmem_alloc
 *
 * Since transmit from skb destructor is forbidden, we use a tasklet
 * to process all sockets that eventually need to send more skbs.
 * We use one tasklet per cpu, with its own queue of sockets.
 */
/* TSQ限制的是在qdisc+dev queue中的数据包总量，并不是sndbuf的大小，更不是cwnd的大小 */
struct tsq_tasklet {
	struct tasklet_struct	tasklet;
	struct list_head	head; /* queue of tcp sockets */
};
static DEFINE_PER_CPU(struct tsq_tasklet, tsq_tasklet);

static void tcp_tsq_handler(struct sock *sk)
{
	if ((1 << sk->sk_state) &
	    (TCPF_ESTABLISHED | TCPF_FIN_WAIT1 | TCPF_CLOSING |
	     TCPF_CLOSE_WAIT  | TCPF_LAST_ACK))
		tcp_write_xmit(sk, tcp_current_mss(sk), 0, 0, GFP_ATOMIC);
}
/*
 * One tasklest per cpu tries to send more skbs.
 * We run in tasklet context but need to disable irqs when
 * transfering tsq->head because tcp_wfree() might
 * interrupt us (non NAPI drivers)
 */
static void tcp_tasklet_func(unsigned long data)
{
	struct tsq_tasklet *tsq = (struct tsq_tasklet *)data;
	LIST_HEAD(list);
	unsigned long flags;
	struct list_head *q, *n;
	struct tcp_sock *tp;
	struct sock *sk;

	local_irq_save(flags);
	list_splice_init(&tsq->head, &list);
	local_irq_restore(flags);

	list_for_each_safe(q, n, &list) {
		tp = list_entry(q, struct tcp_sock, tsq_node);
		list_del(&tp->tsq_node);

		sk = (struct sock *)tp;
		bh_lock_sock(sk);

		if (!sock_owned_by_user(sk)) {
            /* 接着发送数据 */
			tcp_tsq_handler(sk);
		} else {
			/* defer the work to tcp_release_cb() */
            /* 如果sock被用户占用，则延迟发送。打上DEFERRED标记 */
			set_bit(TCP_TSQ_DEFERRED, &tp->tsq_flags);
		}
		bh_unlock_sock(sk);

        /* 清除TSQ的排队标记 */
		clear_bit(TSQ_QUEUED, &tp->tsq_flags);
        /* TSQ机制下的skb释放放到了这里 */
		sk_free(sk);
	}
}

#define TCP_DEFERRED_ALL ((1UL << TCP_TSQ_DEFERRED) |		\
			  (1UL << TCP_WRITE_TIMER_DEFERRED) |	\
			  (1UL << TCP_DELACK_TIMER_DEFERRED) |	\
			  (1UL << TCP_MTU_REDUCED_DEFERRED))
/**
 * tcp_release_cb - tcp release_sock() callback
 * @sk: socket
 *
 * called from release_sock() to perform protocol dependent
 * actions before socket release.
 */
/* 内核在处理收到的数据包时，如果发现sock被用户占用着，则只能defer 操作
 * 之后在用户释放sock时，根据打上的标志，来接着进行内核想做的事情 */
void tcp_release_cb(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned long flags, nflags;

	/* perform an atomic operation only if at least one flag is set */
	do {
		flags = tp->tsq_flags;
		if (!(flags & TCP_DEFERRED_ALL))
			return;
		nflags = flags & ~TCP_DEFERRED_ALL;
	} while (cmpxchg(&tp->tsq_flags, flags, nflags) != flags);

    /* 之前进行过TSQ DEFER */
	if (flags & (1UL << TCP_TSQ_DEFERRED))
		tcp_tsq_handler(sk);

	if (flags & (1UL << TCP_WRITE_TIMER_DEFERRED)) {
		tcp_write_timer_handler(sk);
		__sock_put(sk);
	}
	if (flags & (1UL << TCP_DELACK_TIMER_DEFERRED)) {
		tcp_delack_timer_handler(sk);
		__sock_put(sk);
	}
	if (flags & (1UL << TCP_MTU_REDUCED_DEFERRED)) {
		sk->sk_prot->mtu_reduced(sk);
		__sock_put(sk);
	}
}
EXPORT_SYMBOL(tcp_release_cb);

/* 目前tcp里面的tasklet主要用于TSQ机制 */
void __init tcp_tasklet_init(void)
{
	int i;

	for_each_possible_cpu(i) {
		struct tsq_tasklet *tsq = &per_cpu(tsq_tasklet, i);

		INIT_LIST_HEAD(&tsq->head);
		tasklet_init(&tsq->tasklet,
			     tcp_tasklet_func,
			     (unsigned long)tsq);
	}
}

/*
 * Write buffer destructor automatically called from kfree_skb.
 * We cant xmit new skbs from this context, as we might already
 * hold qdisc lock.
 */
/* 为什么好端端的应该释放skb的时候，却被复用来作为TSQ新数据的发送呢？
 * 读完一下几点分析，应该就明白了：
 *      a. skb该释放的时候肯定是要释放的。即使在使用TSQ机制时。
 *         TSQ机制中，skb的释放移到了tcp_tasklet_func()中
 *      b. 试想一下skb的释放意味着什么？ skb不再被需要了，说明这个skb已经处理完了
 *      c. 使用sysctl_tcp_limit_output_bytes限制数据的发送后，总要找个机会接着发送吧？
 *      有两种选择：使用一个新的timer，或者找到准确的应该"接着发送的时机"
 *
 *  综上分析：一个skb被处理完之后，就是TSQ机制接着发送数据的最佳、最准确的时机
 *  其实TSQ对应的patch已经解释过了，看来还是要结合patch看代码啊。patch里面的解释太重要的了！
 *      As skb destructor cannot restart xmit itself (as qdisc lock might be
 *      taken at this point), we delegate the work to a tasklet. We use one
 *      tasklet per cpu for performance reasons.
 */
void tcp_wfree(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct tcp_sock *tp = tcp_sk(sk);

    /* 清除THROTTLED标记，并判断上一次是否由于超于阈值限制了数据包的发送 */
	if (test_and_clear_bit(TSQ_THROTTLED, &tp->tsq_flags) &&
        /* 并且原来没有设置过TSQ_QUEUED标记
         * 则设置TSQ_QUEUED标记，并开始继续发送之前被限制发送的数据 */
	    !test_and_set_bit(TSQ_QUEUED, &tp->tsq_flags)) {
		unsigned long flags;
		struct tsq_tasklet *tsq;

		/* Keep a ref on socket.
		 * This last ref will be released in tcp_tasklet_func()
		 */
		atomic_sub(skb->truesize - 1, &sk->sk_wmem_alloc);

		/* queue this socket to tasklet queue */
		local_irq_save(flags);
		tsq = &__get_cpu_var(tsq_tasklet);
		list_add(&tp->tsq_node, &tsq->head);
        /* 调用tcp_tasklet_func()继续发送数据包 */
		tasklet_schedule(&tsq->tasklet);
		local_irq_restore(flags);
	} else {
		sock_wfree(skb);
	}
}

/* This routine actually transmits TCP packets queued in by
 * tcp_do_sendmsg().  This is used by both the initial
 * transmission and possible later retransmissions.
 * All SKB's seen here are completely headerless.  It is our
 * job to build the TCP header, and pass the packet down to
 * IP so it can do the same plus pass the packet off to the
 * device.
 *
 * We are working here with either a clone of the original
 * SKB, or a fresh unique copy made by the retransmit engine.
 */
static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
			    gfp_t gfp_mask)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet;
	struct tcp_sock *tp;
	struct tcp_skb_cb *tcb;
	struct tcp_out_options opts;
	unsigned int tcp_options_size, tcp_header_size;
	struct tcp_md5sig_key *md5;
	struct tcphdr *th;
	int err;

	BUG_ON(!skb || !tcp_skb_pcount(skb));

	/* If congestion control is doing timestamping, we must
	 * take such a timestamp before we potentially clone/copy.
	 */
    /* 记录调用tcp_transmit_skb()时的时间戳 */
	if (icsk->icsk_ca_ops->flags & TCP_CONG_RTT_STAMP)
		__net_timestamp(skb);

	if (likely(clone_it)) {
		const struct sk_buff *fclone = skb + 1;

		if (unlikely(skb->fclone == SKB_FCLONE_ORIG &&
			     fclone->fclone == SKB_FCLONE_CLONE))
			NET_INC_STATS_BH(sock_net(sk),
					 LINUX_MIB_TCPSPURIOUS_RTX_HOSTQUEUES);

		if (unlikely(skb_cloned(skb)))
			skb = pskb_copy(skb, gfp_mask);
		else
			skb = skb_clone(skb, gfp_mask);
		if (unlikely(!skb))
			return -ENOBUFS;
	}

	inet = inet_sk(sk);
	tp = tcp_sk(sk);
    /* 获取skb的cb控制块 */
	tcb = TCP_SKB_CB(skb);
	memset(&opts, 0, sizeof(opts));

    /* 计算SYN包中的option和非SYN包中的option是存在不同的 */
	if (unlikely(tcb->tcp_flags & TCPHDR_SYN))
		tcp_options_size = tcp_syn_options(sk, skb, &opts, &md5);
	else
		tcp_options_size = tcp_established_options(sk, skb, &opts,
							   &md5);
	tcp_header_size = tcp_options_size + sizeof(struct tcphdr);

	if (tcp_packets_in_flight(tp) == 0)
		tcp_ca_event(sk, CA_EVENT_TX_START);

	/* if no packet is in qdisc/device queue, then allow XPS to select
	 * another queue.
	 */
	skb->ooo_okay = sk_wmem_alloc_get(sk) == 0;

    /* 将[data, tail] 扩大为 [data - tcp_header_size, tail]
     * 即根据计算得到的tcp头部大小，调整指针位置 */
	skb_push(skb, tcp_header_size);
    /* 设置传输层协议头位置 */
	skb_reset_transport_header(skb);

    /* skb马上就要从TCP层离开，进入IP层了，
     * 所以如果在TCP层有'析构函数'要被调用的话，就应该在此时调用了。
     * 之后则会重新对'析构函数'进行赋值 */
    /* 其实下面四行代码与skb_set_owner_w()做的事情几乎一样，不同点仅是destructor赋值 */
	skb_orphan(skb);
	skb->sk = sk;
    /* 如果开启TSO机制，则使用tcp_wfree负责销毁skb结构体 */
	skb->destructor = (sysctl_tcp_limit_output_bytes > 0) ?
			  tcp_wfree : sock_wfree;
    /* 增加放入qdisc/device queue中数据的字节数 */
	atomic_add(skb->truesize, &sk->sk_wmem_alloc);

	/* Build TCP header and checksum it. */
    /* th指向传输层的头部 */
	th = tcp_hdr(skb);
	th->source		= inet->inet_sport;
	th->dest		= inet->inet_dport;
	th->seq			= htonl(tcb->seq);
	th->ack_seq		= htonl(tp->rcv_nxt);
    /* 4bits长的 header len域， + tcp flags域 */
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
					tcb->tcp_flags);

    /* 决定TCP头部接收窗口域的值，如果带SYN标记的包，则不允许使用win scaling */
	if (unlikely(tcb->tcp_flags & TCPHDR_SYN)) {
		/* RFC1323: The window in SYN & SYN/ACK segments
		 * is never scaled.
		 */
		th->window	= htons(min(tp->rcv_wnd, 65535U));
	} else {
		th->window	= htons(tcp_select_window(sk));
	}
    /* checksum后续会计算 */
	th->check		= 0;
    /* urgent pointer一般都是null */
	th->urg_ptr		= 0;

	/* The urg_mode check is necessary during a below snd_una win probe */
    /* 如果有一字节的urgent data需要发送 */
	if (unlikely(tcp_urg_mode(tp) && before(tcb->seq, tp->snd_up))) {
        /* urgent point有2字节长度的限制 */
		if (before(tp->snd_up, tcb->seq + 0x10000)) {
            /* 设置urg_ptr和urg标记 */
			th->urg_ptr = htons(tp->snd_up - tcb->seq);
			th->urg = 1;
		} else if (after(tcb->seq + 0xFFFF, tp->snd_nxt)) {
            /* 这里算是一个trick啦 */
			th->urg_ptr = htons(0xFFFF);
			th->urg = 1;
		}
	}

    /* 前面已经过该数据包需要添加哪些选项了，下面进行实际的处理 */
    /* (th + 1)指向了option区域的起始位置 */
	tcp_options_write((__be32 *)(th + 1), tp, &opts);
    /* 不带SYN标记，是一个普通的数据包, 根据情况设置ECN标记 */
	if (likely((tcb->tcp_flags & TCPHDR_SYN) == 0))
		TCP_ECN_send(sk, skb, tcp_header_size);

#ifdef CONFIG_TCP_MD5SIG
	/* Calculate the MD5 hash, as we have all we need now */
	if (md5) {
		sk_nocaps_add(sk, NETIF_F_GSO_MASK);
		tp->af_specific->calc_md5_hash(opts.hash_location,
					       md5, sk, NULL, skb);
	}
#endif

    /* 计算checksum */
	icsk->icsk_af_ops->send_check(sk, skb);

    /* 除了SYN包，其他包都会带ACK标记，自然是likely */
	if (likely(tcb->tcp_flags & TCPHDR_ACK))
        /* 主要是处理delay ack的逻辑 */
		tcp_event_ack_sent(sk, tcp_skb_pcount(skb));

    /* 如果数据部分的大小与头部的大小不一致，则说明同时还发送了数据 */
	if (skb->len != tcp_header_size)
        /* 主要处理idle start */
		tcp_event_data_sent(tp, sk);

	if (after(tcb->end_seq, tp->snd_nxt) || tcb->seq == tcb->end_seq)
        /* 只有发送新数据(带SYN或者FIN标记，也是数据)，或者发送纯ACK时才会记录，
         * 也就是说OUTSEGS不会记录重传包的个数, 这点要谨记！ */
		TCP_ADD_STATS(sock_net(sk), TCP_MIB_OUTSEGS,
			      tcp_skb_pcount(skb));

    /* 将数据包交给ip层接着处理 */
	err = icsk->icsk_af_ops->queue_xmit(skb, &inet->cork.fl);
	if (likely(err <= 0))
		return err;

    /* 如果有ip层处理后返回错误，则要进入CWR状态 */
	tcp_enter_cwr(sk, 1);

	return net_xmit_eval(err);
}

/* This routine just queues the buffer for sending.
 *
 * NOTE: probe0 timer is not checked, do not forget tcp_push_pending_frames,
 * otherwise socket can stall.
 */
static void tcp_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Advance write_seq and place onto the write_queue. */
	tp->write_seq = TCP_SKB_CB(skb)->end_seq;
	skb_header_release(skb);
	tcp_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
}

/* Initialize TSO segments for a packet. */
static void tcp_set_skb_tso_segs(const struct sock *sk, struct sk_buff *skb,
				 unsigned int mss_now)
{
    /* 有以下情况不需要分片
     * 1. 数据的长度小于MSS
     * 2. 网卡不支持GSO
     * 3. 网卡不支持重新计算校验和
     *      -- 要想支持TSO，必须要支持校验和计算，因为将一个大skb拆分
     *         成多个小tcp segments时，是需要重新为这些tcp segment计算校验和的
     */
	if (skb->len <= mss_now || !sk_can_gso(sk) ||
	    skb->ip_summed == CHECKSUM_NONE) {
		/* Avoid the costly divide in the normal
		 * non-TSO case.
		 */
		skb_shinfo(skb)->gso_segs = 1;
		skb_shinfo(skb)->gso_size = 0;
		skb_shinfo(skb)->gso_type = 0;
	} else {
        /* 满足使用TSO的条件，则计算好gso_segs和gso_size */
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss_now);
		skb_shinfo(skb)->gso_size = mss_now;
		skb_shinfo(skb)->gso_type = sk->sk_gso_type;
	}
}

/* When a modification to fackets out becomes necessary, we need to check
 * skb is counted to fackets_out or not.
 */
static void tcp_adjust_fackets_out(struct sock *sk, const struct sk_buff *skb,
				   int decr)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tp->sacked_out || tcp_is_reno(tp))
		return;

	if (after(tcp_highest_sack_seq(tp), TCP_SKB_CB(skb)->seq))
		tp->fackets_out -= decr;
}

/* Pcount in the middle of the write queue got changed, we need to do various
 * tweaks to fix counters
 */
/* 当skb从write queue的半道移除后，要更新相关的计数器 */
static void tcp_adjust_pcount(struct sock *sk, const struct sk_buff *skb, int decr)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->packets_out -= decr;

	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		tp->sacked_out -= decr;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS)
		tp->retrans_out -= decr;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_LOST)
		tp->lost_out -= decr;

	/* Reno case is special. Sigh... */
	if (tcp_is_reno(tp) && decr > 0)
		tp->sacked_out -= min_t(u32, tp->sacked_out, decr);

	tcp_adjust_fackets_out(sk, skb, decr);

	if (tp->lost_skb_hint &&
	    before(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(tp->lost_skb_hint)->seq) &&
	    (tcp_is_fack(tp) || (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)))
		tp->lost_cnt_hint -= decr;

	tcp_verify_left_out(tp);
}

/* Function to create two new TCP segments.  Shrinks the given segment
 * to the specified size and appends a new segment with the rest of the
 * packet to the list.  This won't be called frequently, I hope.
 * Remember, these are still headerless SKBs at this point.
 */
/* tcp层进行分片 */
int tcp_fragment(struct sock *sk, struct sk_buff *skb, u32 len,
		 unsigned int mss_now)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int nsize, old_factor;
	int nlen;
	u8 flags;

	if (WARN_ON(len > skb->len))
		return -EINVAL;

	nsize = skb_headlen(skb) - len;
	if (nsize < 0)
		nsize = 0;

	if (skb_cloned(skb) &&
	    skb_is_nonlinear(skb) &&
	    pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return -ENOMEM;

	/* Get a new skb... force flag on. */
	buff = sk_stream_alloc_skb(sk, nsize, GFP_ATOMIC);
	if (buff == NULL)
		return -ENOMEM; /* We'll just try again later. */

	sk->sk_wmem_queued += buff->truesize;
	sk_mem_charge(sk, buff->truesize);
	nlen = skb->len - len - nsize;
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	TCP_SKB_CB(buff)->tcp_flags = flags;
	TCP_SKB_CB(buff)->sacked = TCP_SKB_CB(skb)->sacked;

	if (!skb_shinfo(skb)->nr_frags && skb->ip_summed != CHECKSUM_PARTIAL) {
		/* Copy and checksum data tail into the new buffer. */
		buff->csum = csum_partial_copy_nocheck(skb->data + len,
						       skb_put(buff, nsize),
						       nsize, 0);

		skb_trim(skb, len);

		skb->csum = csum_block_sub(skb->csum, buff->csum, len);
	} else {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb_split(skb, buff, len);
	}

	buff->ip_summed = skb->ip_summed;

	/* Looks stupid, but our code really uses when of
	 * skbs, which it never sent before. --ANK
	 */
	TCP_SKB_CB(buff)->when = TCP_SKB_CB(skb)->when;
	buff->tstamp = skb->tstamp;

	old_factor = tcp_skb_pcount(skb);

	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(sk, skb, mss_now);
	tcp_set_skb_tso_segs(sk, buff, mss_now);

	/* If this packet has been sent out already, we must
	 * adjust the various packet counters.
	 */
	if (!before(tp->snd_nxt, TCP_SKB_CB(buff)->end_seq)) {
		int diff = old_factor - tcp_skb_pcount(skb) -
			tcp_skb_pcount(buff);

		if (diff)
			tcp_adjust_pcount(sk, skb, diff);
	}

	/* Link BUFF into the send queue. */
	skb_header_release(buff);
	tcp_insert_write_queue_after(skb, buff, sk);

	return 0;
}

/* This is similar to __pskb_pull_head() (it will go to core/skbuff.c
 * eventually). The difference is that pulled data not copied, but
 * immediately discarded.
 */
static void __pskb_trim_head(struct sk_buff *skb, int len)
{
	int i, k, eat;

	eat = min_t(int, len, skb_headlen(skb));
	if (eat) {
		__skb_pull(skb, eat);
		len -= eat;
		if (!len)
			return;
	}
	eat = len;
	k = 0;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int size = skb_frag_size(&skb_shinfo(skb)->frags[i]);

		if (size <= eat) {
			skb_frag_unref(skb, i);
			eat -= size;
		} else {
			skb_shinfo(skb)->frags[k] = skb_shinfo(skb)->frags[i];
			if (eat) {
				skb_shinfo(skb)->frags[k].page_offset += eat;
				skb_frag_size_sub(&skb_shinfo(skb)->frags[k], eat);
				eat = 0;
			}
			k++;
		}
	}
	skb_shinfo(skb)->nr_frags = k;

	skb_reset_tail_pointer(skb);
	skb->data_len -= len;
	skb->len = skb->data_len;
}

/* Remove acked data from a packet in the transmit queue. */
int tcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len)
{
	if (skb_unclone(skb, GFP_ATOMIC))
		return -ENOMEM;

	__pskb_trim_head(skb, len);

	TCP_SKB_CB(skb)->seq += len;
	skb->ip_summed = CHECKSUM_PARTIAL;

	skb->truesize	     -= len;
	sk->sk_wmem_queued   -= len;
	sk_mem_uncharge(sk, len);
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);

	/* Any change of skb->len requires recalculation of tso factor. */
	if (tcp_skb_pcount(skb) > 1)
		tcp_set_skb_tso_segs(sk, skb, tcp_skb_mss(skb));

	return 0;
}

/* Calculate MSS not accounting any TCP options.  */
static inline int __tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;

	/* Calculate base mss without TCP options:
	   It is MMS_S - sizeof(tcphdr) of rfc1122
	 */
	mss_now = pmtu - icsk->icsk_af_ops->net_header_len - sizeof(struct tcphdr);

	/* IPv6 adds a frag_hdr in case RTAX_FEATURE_ALLFRAG is set */
	if (icsk->icsk_af_ops->net_frag_header_len) {
		const struct dst_entry *dst = __sk_dst_get(sk);

		if (dst && dst_allfrag(dst))
			mss_now -= icsk->icsk_af_ops->net_frag_header_len;
	}

	/* Clamp it (mss_clamp does not include tcp options) */
	if (mss_now > tp->rx_opt.mss_clamp)
		mss_now = tp->rx_opt.mss_clamp;

	/* Now subtract optional transport overhead */
	mss_now -= icsk->icsk_ext_hdr_len;

	/* Then reserve room for full set of TCP options and 8 bytes of data */
	if (mss_now < 48)
		mss_now = 48;
	return mss_now;
}

/* Calculate MSS. Not accounting for SACKs here.  */
int tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
	/* Subtract TCP options size, not including SACKs */
	return __tcp_mtu_to_mss(sk, pmtu) -
	       (tcp_sk(sk)->tcp_header_len - sizeof(struct tcphdr));
}

/* Inverse of above */
int tcp_mss_to_mtu(struct sock *sk, int mss)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	int mtu;

	mtu = mss +
	      tp->tcp_header_len +
	      icsk->icsk_ext_hdr_len +
	      icsk->icsk_af_ops->net_header_len;

	/* IPv6 adds a frag_hdr in case RTAX_FEATURE_ALLFRAG is set */
	if (icsk->icsk_af_ops->net_frag_header_len) {
		const struct dst_entry *dst = __sk_dst_get(sk);

		if (dst && dst_allfrag(dst))
			mtu += icsk->icsk_af_ops->net_frag_header_len;
	}
	return mtu;
}

/* MTU probing init per socket */
/* MTU probe机制初始化，系统默认是关闭的! */
void tcp_mtup_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_mtup.enabled = sysctl_tcp_mtu_probing > 1;
	icsk->icsk_mtup.search_high = tp->rx_opt.mss_clamp + sizeof(struct tcphdr) +
			       icsk->icsk_af_ops->net_header_len;
	icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, sysctl_tcp_base_mss);
	icsk->icsk_mtup.probe_size = 0;
}
EXPORT_SYMBOL(tcp_mtup_init);

/* This function synchronize snd mss to current pmtu/exthdr set.

   tp->rx_opt.user_mss is mss set by user by TCP_MAXSEG. It does NOT counts
   for TCP options, but includes only bare TCP header.

   tp->rx_opt.mss_clamp is mss negotiated at connection setup.
   It is minimum of user_mss and mss received with SYN.
   It also does not include TCP options.

   inet_csk(sk)->icsk_pmtu_cookie is last pmtu, seen by this function.

   tp->mss_cache is current effective sending mss, including
   all tcp options except for SACKs. It is evaluated,
   taking into account current pmtu, but never exceeds
   tp->rx_opt.mss_clamp.

   NOTE1. rfc1122 clearly states that advertised MSS
   DOES NOT include either tcp or ip options.

   NOTE2. inet_csk(sk)->icsk_pmtu_cookie and tp->mss_cache
   are READ ONLY outside this function.		--ANK (980731)
 */
unsigned int tcp_sync_mss(struct sock *sk, u32 pmtu)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;

	if (icsk->icsk_mtup.search_high > pmtu)
		icsk->icsk_mtup.search_high = pmtu;

	mss_now = tcp_mtu_to_mss(sk, pmtu);
	mss_now = tcp_bound_to_half_wnd(tp, mss_now);

	/* And store cached results */
	icsk->icsk_pmtu_cookie = pmtu;
	if (icsk->icsk_mtup.enabled)
		mss_now = min(mss_now, tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low));
	tp->mss_cache = mss_now;

	return mss_now;
}
EXPORT_SYMBOL(tcp_sync_mss);

/* Compute the current effective MSS, taking SACKs and IP options,
 * and even PMTU discovery events into account.
 */
unsigned int tcp_current_mss(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct dst_entry *dst = __sk_dst_get(sk);
	u32 mss_now;
	unsigned int header_len;
	struct tcp_out_options opts;
	struct tcp_md5sig_key *md5;

	mss_now = tp->mss_cache;

	if (dst) {
		u32 mtu = dst_mtu(dst);
		if (mtu != inet_csk(sk)->icsk_pmtu_cookie)
			mss_now = tcp_sync_mss(sk, mtu);
	}

	header_len = tcp_established_options(sk, NULL, &opts, &md5) +
		     sizeof(struct tcphdr);
	/* The mss_cache is sized based on tp->tcp_header_len, which assumes
	 * some common options. If this is an odd packet (because we have SACK
	 * blocks etc) then our calculated header_len will be different, and
	 * we have to adjust mss_now correspondingly */
	if (header_len != tp->tcp_header_len) {
		int delta = (int) header_len - tp->tcp_header_len;
		mss_now -= delta;
	}

	return mss_now;
}

/* Congestion window validation. (RFC2861) */
/* TODO: 读最新的RFC7661 */
static void tcp_cwnd_validate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->packets_out >= tp->snd_cwnd) {
		/* Network is feed fully. */
		tp->snd_cwnd_used = 0;
		tp->snd_cwnd_stamp = tcp_time_stamp;
	} else {
		/* Network starves. */
		if (tp->packets_out > tp->snd_cwnd_used)
			tp->snd_cwnd_used = tp->packets_out;

        /* 如果启用了slow start after idle
         * 当cwnd有一个RTO没有被变动过, 则降低cwnd */
		if (sysctl_tcp_slow_start_after_idle &&
		    (s32)(tcp_time_stamp - tp->snd_cwnd_stamp) >= inet_csk(sk)->icsk_rto)
			tcp_cwnd_application_limited(sk);
	}
}

/* Returns the portion of skb which can be sent right away without
 * introducing MSS oddities to segment boundaries. In rare cases where
 * mss_now != mss_cache, we will request caller to create a small skb
 * per input skb which could be mostly avoided here (if desired).
 *
 * We explicitly want to create a request for splitting write queue tail
 * to a small skb for Nagle purposes while avoiding unnecessary modulos,
 * thus all the complexity (cwnd_len is always MSS multiple which we
 * return whenever allowed by the other factors). Basically we need the
 * modulo only when the receiver window alone is the limiting factor or
 * when we would be allowed to send the split-due-to-Nagle skb fully.
 */
/* 在支持TSO时，如果skb长度= n * MSS + m，该函数的核心作用就是返回n*MSS */
static unsigned int tcp_mss_split_point(const struct sock *sk, const struct sk_buff *skb,
					unsigned int mss_now, unsigned int max_segs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 needed, window, max_len;

	window = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;
	max_len = mss_now * max_segs;

    /* 如果rwnd用空间发送，并且skb不是最后一个SKB，那么直接发送所有数据 */
	if (likely(max_len <= window && skb != tcp_write_queue_tail(sk)))
		return max_len;

	needed = min(skb->len, window);

	if (max_len <= needed)
		return max_len;

	return needed - needed % mss_now;
}

/* Can at least one segment of SKB be sent right now, according to the
 * congestion window rules?  If so, return how many segments are allowed.
 */
/* 计算cwnd还允许发送多少数据包 */
static inline unsigned int tcp_cwnd_test(const struct tcp_sock *tp,
					 const struct sk_buff *skb)
{
	u32 in_flight, cwnd;

	/* Don't be strict about the congestion window for the final FIN.  */
    /* 如果是最后一个FIN包，则强制允许发送 */
	if ((TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) &&
	    tcp_skb_pcount(skb) == 1)
		return 1;

	in_flight = tcp_packets_in_flight(tp);
	cwnd = tp->snd_cwnd;
	if (in_flight < cwnd)
		return (cwnd - in_flight);

	return 0;
}

/* Initialize TSO state of a skb.
 * This must be invoked the first time we consider transmitting
 * SKB onto the wire.
 */
/* 初始化一个skb中关于tso的信息，返回值是这个skb包含的数据段的个数 */
static int tcp_init_tso_segs(const struct sock *sk, struct sk_buff *skb,
			     unsigned int mss_now)
{
    /* 对于TCP协议而言，GSO就是TSO */
	int tso_segs = tcp_skb_pcount(skb);

    /* 如果未分片，或者进行了分片但大小不是mss_now，则要进一步处理 */
	if (!tso_segs || (tso_segs > 1 && tcp_skb_mss(skb) != mss_now)) {
        /* 重新计算gso_size和gso_segs */
		tcp_set_skb_tso_segs(sk, skb, mss_now);
		tso_segs = tcp_skb_pcount(skb);
	}
	return tso_segs;
}

/* Minshall's variant of the Nagle send check. */
/* 判断最近的一次发送small packet是否被ack了
 * 如果被ack了，则返回false */
static inline bool tcp_minshall_check(const struct tcp_sock *tp)
{
	return after(tp->snd_sml, tp->snd_una) &&
		!after(tp->snd_sml, tp->snd_nxt);
}

/* Return false, if packet can be sent now without violation Nagle's rules:
 * 1. It is full sized.
 * 2. Or it contains FIN. (already checked by caller)
 * 3. Or TCP_CORK is not set, and TCP_NODELAY is set.
 * 4. Or TCP_CORK is not set, and all sent packets are ACKed.
 *    With Minshall's modification: all sent small packets are ACKed.
 */
/* 上面的注释非常准确, 也非常易读就不直接解释了
 * 下面翻过来总结一下内核会限制发送小包需要满足的条件：
 * 1. 此skb是发送队列的最后一个包   -- 这样它才可能由于应用层有新数据要发而增长
 * 2. 发送的不是紧急数据，也不带FIN标记
 * 3. skb的大小小于mss_now          -- 不是满负荷的
 * 4. 设置了TCP_CORK
 *    或者没有设置TCP_CORK，但也没有设置TCP_NODELAY，同时网络中存在未被确认的(小)数据包
 *
 * 可见Nagle被使用的条件是比较苛刻的, 所以一般都是unlikely */
static inline bool tcp_nagle_check(const struct tcp_sock *tp,
				  const struct sk_buff *skb,
				  unsigned int mss_now, int nonagle)
{
	return skb->len < mss_now &&
		((nonagle & TCP_NAGLE_CORK) ||
		 (!nonagle && tp->packets_out && tcp_minshall_check(tp)));
}

/* Return true if the Nagle test allows this packet to be
 * sent now.
 */
static inline bool tcp_nagle_test(const struct tcp_sock *tp, const struct sk_buff *skb,
				  unsigned int cur_mss, int nonagle)
{
	/* Nagle rule does not apply to frames, which sit in the middle of the
	 * write_queue (they have no chances to get new data).
	 *
	 * This is implemented in the callers, where they modify the 'nonagle'
	 * argument based upon the location of SKB in the send queue.
	 */
    /* 如果skb不是队尾的，那么nonagle参数会强制设置为TCP_NAGLE_PUSH
     * 从而该skb不会受到限制, 能立即发送出去 */
	if (nonagle & TCP_NAGLE_PUSH)
		return true;

	/* Don't use the nagle rule for urgent data (or for the final FIN). */
	if (tcp_urg_mode(tp) || (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN))
		return true;

	if (!tcp_nagle_check(tp, skb, cur_mss, nonagle))
		return true;

	return false;
}

/* Does at least the first segment of SKB fit into the send window? */
/* 判断rwnd是否允许至少一个数据包发出去 */
static bool tcp_snd_wnd_test(const struct tcp_sock *tp,
			     const struct sk_buff *skb,
			     unsigned int cur_mss)
{
	u32 end_seq = TCP_SKB_CB(skb)->end_seq;

	if (skb->len > cur_mss)
		end_seq = TCP_SKB_CB(skb)->seq + cur_mss;

	return !after(end_seq, tcp_wnd_end(tp));
}

/* This checks if the data bearing packet SKB (usually tcp_send_head(sk))
 * should be put on the wire right now.  If so, it returns the number of
 * packets allowed by the congestion window.
 */
/* 返回当前允许发送的数据包的个数 */
static unsigned int tcp_snd_test(const struct sock *sk, struct sk_buff *skb,
				 unsigned int cur_mss, int nonagle)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned int cwnd_quota;

    /* 进行TSO分片信息的初始化, 会更新skb_shinfo(skb)->gso_XXXX相关域 */
	tcp_init_tso_segs(sk, skb, cur_mss);

    /* 如果nagle算法不允许发送，则返回0 */
	if (!tcp_nagle_test(tp, skb, cur_mss, nonagle))
		return 0;

    /* 先计算cwnd的额度 */
	cwnd_quota = tcp_cwnd_test(tp, skb);
    /* 在考虑rwnd的额度 */
	if (cwnd_quota && !tcp_snd_wnd_test(tp, skb, cur_mss))
		cwnd_quota = 0;

	return cwnd_quota;
}

/* Test if sending is allowed right now. */
/* 判断是否可以发送新数据 */
bool tcp_may_send_now(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = tcp_send_head(sk);

	return skb &&
		tcp_snd_test(sk, skb, tcp_current_mss(sk),
			     (tcp_skb_is_last(sk, skb) ?
			      tp->nonagle : TCP_NAGLE_PUSH));
}

/* Trim TSO SKB to LEN bytes, put the remaining data into a new packet
 * which is put after SKB on the list.  It is very much like
 * tcp_fragment() except that it may make several kinds of assumptions
 * in order to speed up the splitting operation.  In particular, we
 * know that all the data is in scatter-gather pages, and that the
 * packet has never been sent out before (and thus is not cloned).
 */
/* 将长度为len + x的skb，分割成长度为len的skb_1和长度为x的skb_2 */
static int tso_fragment(struct sock *sk, struct sk_buff *skb, unsigned int len,
			unsigned int mss_now, gfp_t gfp)
{
	struct sk_buff *buff;
	int nlen = skb->len - len;
	u8 flags;

	/* All of a TSO frame must be composed of paged data.  */
	if (skb->len != skb->data_len)
		return tcp_fragment(sk, skb, len, mss_now);

	buff = sk_stream_alloc_skb(sk, 0, gfp);
	if (unlikely(buff == NULL))
		return -ENOMEM;

	sk->sk_wmem_queued += buff->truesize;
	sk_mem_charge(sk, buff->truesize);
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	TCP_SKB_CB(buff)->tcp_flags = flags;

	/* This packet was never sent out yet, so no SACK bits. */
	TCP_SKB_CB(buff)->sacked = 0;

	buff->ip_summed = skb->ip_summed = CHECKSUM_PARTIAL;
	skb_split(skb, buff, len);

	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(sk, skb, mss_now);
	tcp_set_skb_tso_segs(sk, buff, mss_now);

	/* Link BUFF into the send queue. */
	skb_header_release(buff);
	tcp_insert_write_queue_after(skb, buff, sk);

	return 0;
}

/* Try to defer sending, if possible, in order to minimize the amount
 * of TSO splitting we do.  View it as a kind of TSO Nagle test.
 *
 * This algorithm is from John Heffner.
 */
/* 判断是否应该延迟数据的发送，来减少TSO分段的次数，从而减小CPU负载
 * 返回1表示要defer */
static bool tcp_tso_should_defer(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	u32 send_win, cong_win, limit, in_flight;
	int win_divisor;

    /* 如果带FIN标记，则应该马上发送 */
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
		goto send_now;

    /* 如果是处于Open状态，则马上发送 */
	if (icsk->icsk_ca_state != TCP_CA_Open)
		goto send_now;

	/* Defer for less than two clock ticks. */
    /* tso_deferred最多延迟2ms */
	if (tp->tso_deferred &&
	    (((u32)jiffies << 1) >> 1) - (tp->tso_deferred >> 1) > 1)
		goto send_now;

	in_flight = tcp_packets_in_flight(tp);

	BUG_ON(tcp_skb_pcount(skb) <= 1 || (tp->snd_cwnd <= in_flight));

    /* 通告窗口的剩余大小，字节数 */
	send_win = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

	/* From in_flight test above, we know that cwnd > in_flight.  */
    /* 拥塞窗口剩余大小，字节数 */
	cong_win = (tp->snd_cwnd - in_flight) * tp->mss_cache;

    /* 取min作为发送限制 */
	limit = min(send_win, cong_win);

	/* If a full-sized TSO skb can be sent, do it. */
    /* sk_gso_max_size一般是64kb */
	if (limit >= min_t(unsigned int, sk->sk_gso_max_size,
			   sk->sk_gso_max_segs * tp->mss_cache))
		goto send_now;

	/* Middle in queue won't get any more data, full sendable already? */
    /* 如果skb不位于队尾，则它的长度不会更改了，故只要limit允许发送就应该立即发送 */
	if ((skb != tcp_write_queue_tail(sk)) && (limit >= skb->len))
		goto send_now;

	win_divisor = ACCESS_ONCE(sysctl_tcp_tso_win_divisor);
    /* 如果设置了sysctl_tcp_tso_win_divisor，
     * 如果有超过chunk/win_divisor的剩余空间，则应该立即发送数据 */
	if (win_divisor) {
        /* 一个RTT内允许发送的字节数 */
		u32 chunk = min(tp->snd_wnd, tp->snd_cwnd * tp->mss_cache);

		/* If at least some fraction of a window is available,
		 * just use it.
		 */
		chunk /= win_divisor;   /* 单个TSO段允许的最大发送量，如果limit超过这个值，则也是可以立即发送的 */
		if (limit >= chunk)
			goto send_now;
	} else {
		/* Different approach, try not to defer past a single
		 * ACK.  Receiver should ACK every other full sized
		 * frame, so if we have space for more than 3 frames
		 * then send now.
		 */
        /* 如果没有配置sysctl_tcp_tso_win_divisor，则TSO最多defer3个数据包的发送
         * 如果limit超过了这个值，则也应该立即发送 */
		if (limit > tcp_max_tso_deferred_mss(tp) * tp->mss_cache)
			goto send_now;
	}

	/* Ok, it looks like it is advisable to defer.
	 * Do not rearm the timer if already set to not break TCP ACK clocking.
	 */
    /* tso_defered被设置为单数 */
	if (!tp->tso_deferred)
		tp->tso_deferred = 1 | (jiffies << 1);

	return true;

send_now:
	tp->tso_deferred = 0;
	return false;
}

/* Create a new MTU probe if we are ready.
 * MTU probe is regularly attempting to increase the path MTU by
 * deliberately sending larger packets.  This discovers routing
 * changes resulting in larger path MTUs.
 *
 * Returns 0 if we should wait to probe (no cwnd available),
 *         1 if a probe was sent,
 *         -1 otherwise
 */
static int tcp_mtu_probe(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct sk_buff *skb, *nskb, *next;
	int len;
	int probe_size;
	int size_needed;
	int copy;
	int mss_now;

	/* Not currently probing/verifying,
	 * not in recovery,
	 * have enough cwnd, and
	 * not SACKing (the variable headers throw things off) */
    /* 默认情况下MTU probeing是关闭的，故直接返回-1 */
	if (!icsk->icsk_mtup.enabled ||
	    icsk->icsk_mtup.probe_size ||
	    inet_csk(sk)->icsk_ca_state != TCP_CA_Open ||
	    tp->snd_cwnd < 11 ||
	    tp->rx_opt.num_sacks || tp->rx_opt.dsack)
		return -1;

	/* Very simple search strategy: just double the MSS. */
	mss_now = tcp_current_mss(sk);
	probe_size = 2 * tp->mss_cache;
	size_needed = probe_size + (tp->reordering + 1) * tp->mss_cache;
	if (probe_size > tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_high)) {
		/* TODO: set timer for probe_converge_event */
		return -1;
	}

	/* Have enough data in the send queue to probe? */
	if (tp->write_seq - tp->snd_nxt < size_needed)
		return -1;

	if (tp->snd_wnd < size_needed)
		return -1;
	if (after(tp->snd_nxt + size_needed, tcp_wnd_end(tp)))
		return 0;

	/* Do we need to wait to drain cwnd? With none in flight, don't stall */
	if (tcp_packets_in_flight(tp) + 2 > tp->snd_cwnd) {
		if (!tcp_packets_in_flight(tp))
			return -1;
		else
			return 0;
	}

	/* We're allowed to probe.  Build it now. */
	if ((nskb = sk_stream_alloc_skb(sk, probe_size, GFP_ATOMIC)) == NULL)
		return -1;
	sk->sk_wmem_queued += nskb->truesize;
	sk_mem_charge(sk, nskb->truesize);

	skb = tcp_send_head(sk);

	TCP_SKB_CB(nskb)->seq = TCP_SKB_CB(skb)->seq;
	TCP_SKB_CB(nskb)->end_seq = TCP_SKB_CB(skb)->seq + probe_size;
	TCP_SKB_CB(nskb)->tcp_flags = TCPHDR_ACK;
	TCP_SKB_CB(nskb)->sacked = 0;
	nskb->csum = 0;
	nskb->ip_summed = skb->ip_summed;

	tcp_insert_write_queue_before(nskb, skb, sk);

	len = 0;
	tcp_for_write_queue_from_safe(skb, next, sk) {
		copy = min_t(int, skb->len, probe_size - len);
		if (nskb->ip_summed)
			skb_copy_bits(skb, 0, skb_put(nskb, copy), copy);
		else
			nskb->csum = skb_copy_and_csum_bits(skb, 0,
							    skb_put(nskb, copy),
							    copy, nskb->csum);

		if (skb->len <= copy) {
			/* We've eaten all the data from this skb.
			 * Throw it away. */
			TCP_SKB_CB(nskb)->tcp_flags |= TCP_SKB_CB(skb)->tcp_flags;
			tcp_unlink_write_queue(skb, sk);
			sk_wmem_free_skb(sk, skb);
		} else {
			TCP_SKB_CB(nskb)->tcp_flags |= TCP_SKB_CB(skb)->tcp_flags &
						   ~(TCPHDR_FIN|TCPHDR_PSH);
			if (!skb_shinfo(skb)->nr_frags) {
				skb_pull(skb, copy);
				if (skb->ip_summed != CHECKSUM_PARTIAL)
					skb->csum = csum_partial(skb->data,
								 skb->len, 0);
			} else {
				__pskb_trim_head(skb, copy);
				tcp_set_skb_tso_segs(sk, skb, mss_now);
			}
			TCP_SKB_CB(skb)->seq += copy;
		}

		len += copy;

		if (len >= probe_size)
			break;
	}
	tcp_init_tso_segs(sk, nskb, nskb->len);

	/* We're ready to send.  If this fails, the probe will
	 * be resegmented into mss-sized pieces by tcp_write_xmit(). */
	TCP_SKB_CB(nskb)->when = tcp_time_stamp;
	if (!tcp_transmit_skb(sk, nskb, 1, GFP_ATOMIC)) {
		/* Decrement cwnd here because we are sending
		 * effectively two packets. */
		tp->snd_cwnd--;
		tcp_event_new_data_sent(sk, nskb);

		icsk->icsk_mtup.probe_size = tcp_mss_to_mtu(sk, nskb->len);
		tp->mtu_probe.probe_seq_start = TCP_SKB_CB(nskb)->seq;
		tp->mtu_probe.probe_seq_end = TCP_SKB_CB(nskb)->end_seq;

		return 1;
	}

	return -1;
}

/* This routine writes packets to the network.  It advances the
 * send_head.  This happens as incoming acks open up the remote
 * window for us.
 *
 * LARGESEND note: !tcp_urg_mode is overkill, only frames between
 * snd_up-64k-mss .. snd_up cannot be large. However, taking into
 * account rare use of URG, this is not a big flaw.
 *
 * Send at most one packet when push_one > 0. Temporarily ignore
 * cwnd limit to force at most one packet out when push_one == 2.

 * Returns true, if no segments are in flight and we have queued segments,
 * but cannot send anything now because of SWS or another problem.
 * 说白了，就是遇到zero window的时候，return true
 */
/* 负责将数据发送出去, 该函数只负责发送新数据 */
/* 关于push_one的作用已经在英文注释解释了，补充一点: push_one == 2的场景目前仅用在TLP机制中 */
static bool tcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
			   int push_one, gfp_t gfp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	unsigned int tso_segs, sent_pkts;
	int cwnd_quota;
	int result;

	sent_pkts = 0;

	if (!push_one) {
		/* Do MTU probing. */
        /* 默认没有开启，直接返回-1 */
		result = tcp_mtu_probe(sk);
		if (!result) {
			return false;
		} else if (result > 0) {
            /* 记录MTU probing已经发送的一个数据包 */
			sent_pkts = 1;
		}
	}

    /* 从send_head处开始发送 */
	while ((skb = tcp_send_head(sk))) {
		unsigned int limit;


        /* 返回该SKB对应的需要拆分的数量 */
		tso_segs = tcp_init_tso_segs(sk, skb, mss_now);
		BUG_ON(!tso_segs);

		if (unlikely(tp->repair) && tp->repair_queue == TCP_SEND_QUEUE)
			goto repair; /* Skip network transmission */

        /* 检查cwnd是否允许发送数据 */
		cwnd_quota = tcp_cwnd_test(tp, skb);
		if (!cwnd_quota) {
			if (push_one == 2)
				/* Force out a loss probe pkt. */
				cwnd_quota = 1;
			else
				break;
		}

        /* 检查rwnd是否允许发送数据 */
		if (unlikely(!tcp_snd_wnd_test(tp, skb, mss_now)))
			break;

		if (tso_segs == 1) {
            /* 判断nagle 算法是否允许数据发送出去 */
			if (unlikely(!tcp_nagle_test(tp, skb, mss_now,
                             /* 如果不是最后一个SKB，则可以直接发送出去 */
						     (tcp_skb_is_last(sk, skb) ?
						      nonagle : TCP_NAGLE_PUSH))))
				break;
		} else {
            /* 如果该skb启用的TSO，则需要判断是否应该延迟该数据包的发送 */
			if (!push_one && tcp_tso_should_defer(sk, skb))
				break;
		}

		/* TSQ : sk_wmem_alloc accounts skb truesize,
		 * including skb overhead. But thats OK.
		 */
        /* 如果单条TCP流提交到qdisc+dev queue中的SKB占用内存超过阈值，则标记为TSQ_THROTTLED，并停止发送 */
		if (atomic_read(&sk->sk_wmem_alloc) >= sysctl_tcp_limit_output_bytes) {
			set_bit(TSQ_THROTTLED, &tp->tsq_flags);
			break;
		}
		limit = mss_now;
		if (tso_segs > 1 && !tcp_urg_mode(tp))
            /* 计算skb需要分片的位置 */
			limit = tcp_mss_split_point(sk, skb, mss_now,
                            /* 注意传入的参数，考虑到了cwnd */
						    min_t(unsigned int,
							  cwnd_quota,
							  sk->sk_gso_max_segs));

        /* 如果需要分片(len > limit), 则进行tso分片 */
        /* 一般情况下，是返回mss_now * gso_max_segs，基本不用触发分片 */
		if (skb->len > limit &&
		    unlikely(tso_fragment(sk, skb, limit, mss_now, gfp)))
			break;

        /* 记录该skb发送出去的时间 */
		TCP_SKB_CB(skb)->when = tcp_time_stamp;

        /* 发送skb, 其实是发送一份clone出去，该skb还是会保留在TCP层的发送队列中, 直到被按序确认掉 */
		if (unlikely(tcp_transmit_skb(sk, skb, 1, gfp)))
			break;

repair:
		/* Advance the send_head.  This one is sent out.
		 * This call will increment packets_out.
		 */
		tcp_event_new_data_sent(sk, skb);

        /* 如果发送了一个小包，则更新snd_sml指针 */
		tcp_minshall_update(tp, mss_now, skb);
        /* sent_pkts记录该次遍历发送出去的数据包个数 */
		sent_pkts += tcp_skb_pcount(skb);

        /* 如果最多只发送一个数据包，则停止发送 */
		if (push_one)
			break;
	}

	if (likely(sent_pkts)) {
        /* 如果是在PRR算法阶段，即快速恢复阶段，则记录PRR算法发送出去的数据包 */
		if (tcp_in_cwnd_reduction(sk))
			tp->prr_out += sent_pkts;

		/* Send one loss probe per tail loss episode. */
        /* 尝试安装PTO timer */
		if (push_one != 2)
			tcp_schedule_loss_probe(sk);
		tcp_cwnd_validate(sk);
        /* 返回false，表示没有发生错误 */
		return false;
	}
    /* 如果TLP失败，则返回true
     * 或
     * 如果zero window出现了, 则返回true
     * anyway, tcp_write_xmit()返回返回true其实是错误 */
	return (push_one == 2) || (!tp->packets_out && tcp_send_head(sk));
}

/* 尝试安装Probe Timer (PTO), 返回true表示安装成功 */
bool tcp_schedule_loss_probe(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 timeout, tlp_time_stamp, rto_time_stamp;
	u32 rtt = tp->srtt >> 3;

    /* 如果已经安装了ER timer，则放弃安装PTO */
	if (WARN_ON(icsk->icsk_pending == ICSK_TIME_EARLY_RETRANS))
		return false;

	/* No consecutive loss probes. */
    /* 如果已经安装了PTO，则放弃安装,重设RTO timer */
	if (WARN_ON(icsk->icsk_pending == ICSK_TIME_LOSS_PROBE)) {
		tcp_rearm_rto(sk);
		return false;
	}
	/* Don't do any loss probe on a Fast Open connection before 3WHS
	 * finishes.
	 */
	if (sk->sk_state == TCP_SYN_RECV)
		return false;

	/* TLP is only scheduled when next timer event is RTO. */
	if (icsk->icsk_pending != ICSK_TIME_RETRANS)
		return false;

	/* Schedule a loss probe in 2*RTT for SACK capable connections
	 * in Open state, that are either limited by cwnd or application.
	 */
	if (sysctl_tcp_early_retrans < 3 ||     /* 如果没开TLP */
        !rtt ||                             /* 没有RTT sample可用，没法设置PTO */
        !tp->packets_out ||                 /* 没有未被确认的数据包 */
	    !tcp_is_sack(tp) ||                 /* TLP依赖于SACK选项 */
        inet_csk(sk)->icsk_ca_state != TCP_CA_Open)     /* 只有在Open状态才设置PTO */
		return false;

    /* 如果有新数据可以待发送，且cwnd允许，也不用设置PTO */
	if ((tp->snd_cwnd > tcp_packets_in_flight(tp)) &&
	     tcp_send_head(sk))
		return false;

	/* Probe timeout is at least 1.5*rtt + TCP_DELACK_MAX to account
	 * for delayed ack when there's one outstanding packet.
	 */
	timeout = rtt << 1;
	if (tp->packets_out == 1)
		timeout = max_t(u32, timeout,
				(rtt + (rtt >> 1) + TCP_DELACK_MAX));
	timeout = max_t(u32, timeout, msecs_to_jiffies(10));

	/* If RTO is shorter, just schedule TLP in its place. */
    /* 说白了就是PTO = min(PTO, RTO) */
	tlp_time_stamp = tcp_time_stamp + timeout;
	rto_time_stamp = (u32)inet_csk(sk)->icsk_timeout;
    /* 注意这个地方s32类型的使用 */
	if ((s32)(tlp_time_stamp - rto_time_stamp) > 0) {
		s32 delta = rto_time_stamp - tcp_time_stamp;
		if (delta > 0)
			timeout = delta;
	}

    /* 至此可以设置PTO, PTO超时的处理函数是tcp_send_loss_probe */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_LOSS_PROBE, timeout,
				  TCP_RTO_MAX);
	return true;
}

/* When probe timeout (PTO) fires, send a new segment if one exists, else
 * retransmit the last segment.
 */
void tcp_send_loss_probe(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int pcount;
	int mss = tcp_current_mss(sk);
	int err = -1;

    /* 如果有新数据可以发送，则发送新数据进行loss probe */
    /* TLP用push_one参数=2这个trick来区分是正常的发送包，
     * 还是loss probe */
	if (tcp_send_head(sk) != NULL) {
		err = tcp_write_xmit(sk, mss, TCP_NAGLE_OFF, 2, GFP_ATOMIC);
		goto rearm_timer;       /* 重新启动RTO超时定时器 */
	}

	/* At most one outstanding TLP retransmission. */
    /* tlp_high_seq被设置过，说明已经发送了一个TLP包 */
	if (tp->tlp_high_seq)
		goto rearm_timer;

	/* Retransmit last segment. */
    /* 没新数据需要发送时，就发送队尾的skb */
	skb = tcp_write_queue_tail(sk);
	if (WARN_ON(!skb))
		goto rearm_timer;

	pcount = tcp_skb_pcount(skb);
	if (WARN_ON(!pcount))
		goto rearm_timer;

	if ((pcount > 1) && (skb->len > (pcount - 1) * mss)) {
		if (unlikely(tcp_fragment(sk, skb, (pcount - 1) * mss, mss)))
			goto rearm_timer;
		skb = tcp_write_queue_tail(sk);
	}

	if (WARN_ON(!skb || !tcp_skb_pcount(skb)))
		goto rearm_timer;

	/* Probe with zero data doesn't trigger fast recovery. */
	if (skb->len > 0)
		err = __tcp_retransmit_skb(sk, skb);

	/* Record snd_nxt for loss detection. */
	if (likely(!err))
		tp->tlp_high_seq = tp->snd_nxt;     /* 记录发送TLP包时的snd_nxt */

rearm_timer:
    /* 重新安装RTO超时计时器 */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  inet_csk(sk)->icsk_rto,
				  TCP_RTO_MAX);

	if (likely(!err))
        /* 增加发送loss probe的次数，在/proc/net/snmp中可看到 */
		NET_INC_STATS_BH(sock_net(sk),
				 LINUX_MIB_TCPLOSSPROBES);
	return;
}

/* Push out any pending frames which were held back due to
 * TCP_CORK or attempt at coalescing tiny packets.
 * The socket must be locked by the caller.
 */
/* 发送pending在sndbuf中的数据包 */
void __tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,
			       int nonagle)
{
	/* If we are closed, the bytes will have to remain here.
	 * In time closedown will finish, we empty the write queue and
	 * all will be happy.
	 */
	if (unlikely(sk->sk_state == TCP_CLOSE))
		return;

    /* Returns true, if no segments are in flight and we have queued segments,
     * but cannot send anything now because of SWS or another problem.
     * return true的条件：
     * 1. 网络中没有inflight的数据包 &&
     * 2. sndbuf中有等待发送的数据 &&
     * 3. sndbuf中的数据包不能发送
     *
     * 场景： 对端的接收窗口用完了 zero window */
    /* 有数据想发，而未能成功发送时，启动zero window probe timer */
	if (tcp_write_xmit(sk, cur_mss, nonagle, 0,
			   sk_gfp_atomic(sk, GFP_ATOMIC)))
		tcp_check_probe_timer(sk);
}

/* Send _single_ skb sitting at the send head. This function requires
 * true push pending frames to setup probe timer etc.
 */
/* 将发送队列的head数据包发送出去 */
void tcp_push_one(struct sock *sk, unsigned int mss_now)
{
	struct sk_buff *skb = tcp_send_head(sk);

	BUG_ON(!skb || skb->len < mss_now);

	tcp_write_xmit(sk, mss_now, TCP_NAGLE_PUSH, 1, sk->sk_allocation);
}

/* This function returns the amount that we can raise the
 * usable window based on the following constraints
 *
 * 1. The window can never be shrunk once it is offered (RFC 793)
 * 2. We limit memory per socket
 *
 * RFC 1122:
 * "the suggested [SWS] avoidance algorithm for the receiver is to keep
 *  RECV.NEXT + RCV.WIN fixed until:
 *  RCV.BUFF - RCV.USER - RCV.WINDOW >= min(1/2 RCV.BUFF, MSS)"
 *
 * i.e. don't raise the right edge of the window until you can raise
 * it at least MSS bytes.
 *
 * Unfortunately, the recommended algorithm breaks header prediction,
 * since header prediction assumes th->window stays fixed.
 *
 * Strictly speaking, keeping th->window fixed violates the receiver
 * side SWS prevention criteria. The problem is that under this rule
 * a stream of single byte packets will cause the right side of the
 * window to always advance by a single byte.
 *
 * Of course, if the sender implements sender side SWS prevention
 * then this will not be a problem.
 *
 * BSD seems to make the following compromise:
 *
 *	If the free space is less than the 1/4 of the maximum
 *	space available and the free space is less than 1/2 mss,
 *	then set the window to 0.
 *	[ Actually, bsd uses MSS and 1/4 of maximal _window_ ]
 *	Otherwise, just prevent the window from shrinking
 *	and from being larger than the largest representable value.
 *
 * This prevents incremental opening of the window in the regime
 * where TCP is limited by the speed of the reader side taking
 * data out of the TCP receive queue. It does nothing about
 * those cases where the window is constrained on the sender side
 * because the pipeline is full.
 *
 * BSD also seems to "accidentally" limit itself to windows that are a
 * multiple of MSS, at least until the free space gets quite small.
 * This would appear to be a side effect of the mbuf implementation.
 * Combining these two algorithms results in the observed behavior
 * of having a fixed window size at almost all times.
 *
 * Below we obtain similar behavior by forcing the offered window to
 * a multiple of the mss when it is feasible to do so.
 *
 * Note, we don't "adjust" for TIMESTAMP or SACK option bytes.
 * Regular options like TIMESTAMP are taken into account.
 */
u32 __tcp_select_window(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	/* MSS for the peer's data.  Previous versions used mss_clamp
	 * here.  I don't know if the value based on our guesses
	 * of peer's MSS is better for the performance.  It's more correct
	 * but may be worse for the performance because of rcv_mss
	 * fluctuations.  --SAW  1998/11/1
	 */
	int mss = icsk->icsk_ack.rcv_mss;
	int free_space = tcp_space(sk);
	int full_space = min_t(int, tp->window_clamp, tcp_full_space(sk));
	int window;

	if (mss > full_space)
		mss = full_space;

	if (free_space < (full_space >> 1)) {
		icsk->icsk_ack.quick = 0;

		if (sk_under_memory_pressure(sk))
			tp->rcv_ssthresh = min(tp->rcv_ssthresh,
					       4U * tp->advmss);

		if (free_space < mss)
			return 0;
	}

	if (free_space > tp->rcv_ssthresh)
		free_space = tp->rcv_ssthresh;

	/* Don't do rounding if we are using window scaling, since the
	 * scaled window will not line up with the MSS boundary anyway.
	 */
	window = tp->rcv_wnd;
	if (tp->rx_opt.rcv_wscale) {
		window = free_space;

		/* Advertise enough space so that it won't get scaled away.
		 * Import case: prevent zero window announcement if
		 * 1<<rcv_wscale > mss.
		 */
		if (((window >> tp->rx_opt.rcv_wscale) << tp->rx_opt.rcv_wscale) != window)
			window = (((window >> tp->rx_opt.rcv_wscale) + 1)
				  << tp->rx_opt.rcv_wscale);
	} else {
		/* Get the largest window that is a nice multiple of mss.
		 * Window clamp already applied above.
		 * If our current window offering is within 1 mss of the
		 * free space we just keep it. This prevents the divide
		 * and multiply from happening most of the time.
		 * We also don't do any window rounding when the free space
		 * is too small.
		 */
		if (window <= free_space - mss || window > free_space)
			window = (free_space / mss) * mss;
		else if (mss == full_space &&
			 free_space > window + (full_space >> 1))
			window = free_space;
	}

	return window;
}

/* Collapses two adjacent SKB's during retransmission. */
/* 在重传阶段，将skb和skb->next合并 */
static void tcp_collapse_retrans(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *next_skb = tcp_write_queue_next(sk, skb);
	int skb_size, next_skb_size;

	skb_size = skb->len;
	next_skb_size = next_skb->len;

	BUG_ON(tcp_skb_pcount(skb) != 1 || tcp_skb_pcount(next_skb) != 1);

	tcp_highest_sack_combine(sk, next_skb, skb);

    /* 将被动合并的skb从write_queue中移除 */
	tcp_unlink_write_queue(next_skb, sk);

    /* 将next_skb的linear data拷贝的skb中 */
	skb_copy_from_linear_data(next_skb, skb_put(skb, next_skb_size),
				  next_skb_size);

	if (next_skb->ip_summed == CHECKSUM_PARTIAL)
		skb->ip_summed = CHECKSUM_PARTIAL;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		skb->csum = csum_block_add(skb->csum, next_skb->csum, skb_size);

	/* Update sequence range on original skb. */
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(next_skb)->end_seq;

	/* Merge over control information. This moves PSH/FIN etc. over */
	TCP_SKB_CB(skb)->tcp_flags |= TCP_SKB_CB(next_skb)->tcp_flags;

	/* All done, get rid of second SKB and account for it so
	 * packet counting does not break.
	 */
	TCP_SKB_CB(skb)->sacked |= TCP_SKB_CB(next_skb)->sacked & TCPCB_EVER_RETRANS;

	/* changed transmit queue under us so clear hints */
	tcp_clear_retrans_hints_partial(tp);
	if (next_skb == tp->retransmit_skb_hint)
		tp->retransmit_skb_hint = skb;

    /* 由于next_skb从队列中移除了，所以要更新相关计数 */
	tcp_adjust_pcount(sk, next_skb, tcp_skb_pcount(next_skb));

	sk_wmem_free_skb(sk, next_skb);
}

/* Check if coalescing SKBs is legal. */
/* 判断skb能否参与合并 */
static bool tcp_can_collapse(const struct sock *sk, const struct sk_buff *skb)
{
    /* 如果该skb由于TSO包含多个数据包，那么该skb不能参与合并 */
	if (tcp_skb_pcount(skb) > 1)
		return false;
	/* TODO: SACK collapsing could be used to remove this condition */
    /* 如果该skb包含paged data，也不能参与合并 */
	if (skb_shinfo(skb)->nr_frags != 0)
		return false;
    /* 如果只是cloned skb，由于是shared data,没有写权限，也是不能参与合并的 */
    /* ADI中的解释：the original transmission should not be there in the IP or device queue pending for transmission 
     * TODO：确认一下ADI解释是否正确。 */
	if (skb_cloned(skb))
		return false;
    /* 如果是发送队列的head，则也不能参与合并 */
	if (skb == tcp_send_head(sk))
		return false;
	/* Some heurestics for collapsing over SACK'd could be invented */
    /* 如果这个skb已经被ACKED或SACKED，则不能参与合并 */
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		return false;

	return true;
}

/* Collapse packets in the retransmit queue to make to create
 * less packets on the wire. This is only done on retransmission.
 */
/* 重传时，如果skb小于cur_mss，则尝试合并 */
/* 最大就合并一个space大小的skb出来，即cur_mss */
static void tcp_retrans_try_collapse(struct sock *sk, struct sk_buff *to,
				     int space)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = to, *tmp;
	bool first = true;

    /* 默认开启尝试重传合并 */
	if (!sysctl_tcp_retrans_collapse)
		return;
    /* 带SYN标记的包不合并 */
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
		return;

    /* 从to开始遍历, 包括to，因为也要检查to是否符合合并条件 */
	tcp_for_write_queue_from_safe(skb, tmp, sk) {
        /* 如果skb不能参与合并，则放弃继续合并 */
		if (!tcp_can_collapse(sk, skb))
			break;

        /* 如果当前skb能参与合并，则将其考虑其中 */
		space -= skb->len;

		if (first) {
			first = false;
			continue;
		}

        /* 如果space用完了，即长度超过cur_mss了，则停止合并 */
		if (space < 0)
			break;
		/* Punt if not enough space exists in the first SKB for
		 * the data in the second
		 */
        /* 如果to中没有足够的空间，则放弃合并 */
        /* 原则：we are not going to add any data to the paged area nor are we going to reallocate memory
         * in the linear area to accommodate new data(expensive operation) */
		if (skb->len > skb_availroom(to))
			break;

        /* 如果skb的尾序号超出接收窗口限制，则也不能合并 */
		if (after(TCP_SKB_CB(skb)->end_seq, tcp_wnd_end(tp)))
			break;

        /* 至此，就可以将skb合并入to中了 */
		tcp_collapse_retrans(sk, to);
	}
}

/* This retransmits one SKB.  Policy decisions and retransmit queue
 * state updates are done by the caller.  Returns non-zero if an
 * error occurred which prevented the send.
 */
int __tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	unsigned int cur_mss;

	/* Inconslusive MTU probe */
	if (icsk->icsk_mtup.probe_size) {
		icsk->icsk_mtup.probe_size = 0;
	}

	/* Do not sent more than we queued. 1/4 is reserved for possible
	 * copying overhead: fragmentation, tunneling, mangling etc.
	 */
    /* 不考虑重传的话，sk_wmem_alloc不可能超过sk_wmem_queued，只有重传时才可能超过。
     * 来假设一个可能：发送的数据都在qdisc 队列中排着队，而RTO超时后又准备发送数据
     * 到目前为止：认为这种情况发生的概率太低了*/
	if (atomic_read(&sk->sk_wmem_alloc) >
	    min(sk->sk_wmem_queued + (sk->sk_wmem_queued >> 2), sk->sk_sndbuf))
		return -EAGAIN;

	if (before(TCP_SKB_CB(skb)->seq, tp->snd_una)) {
		if (before(TCP_SKB_CB(skb)->end_seq, tp->snd_una))
			BUG();
		if (tcp_trim_head(sk, skb, tp->snd_una - TCP_SKB_CB(skb)->seq))
			return -ENOMEM;
	}

	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	cur_mss = tcp_current_mss(sk);

	/* If receiver has shrunk his window, and skb is out of
	 * new window, do not retransmit it. The exception is the
	 * case, when window is shrunk to zero. In this case
	 * our retransmit serves as a zero window probe.
	 */
	if (!before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp)) &&
	    TCP_SKB_CB(skb)->seq != tp->snd_una)
		return -EAGAIN;

    /* 如果skb超过最新的mss(可能变小), 那么重传时就需要分片 */
	if (skb->len > cur_mss) {
		if (tcp_fragment(sk, skb, cur_mss, cur_mss))
			return -ENOMEM; /* We'll try again later. */
	} else {
		int oldpcount = tcp_skb_pcount(skb);

		if (unlikely(oldpcount > 1)) {
			tcp_init_tso_segs(sk, skb, cur_mss);
			tcp_adjust_pcount(sk, skb, oldpcount - tcp_skb_pcount(skb));
		}
	}

    /* 当skb长度小于cur_mss时，尝试合并skb, 减少重传数据包数量 */
    /* TODO: 为什么该函数的调用出没有判断条件？？？ 任何情况都进入是不是太糙了  */
	tcp_retrans_try_collapse(sk, skb, cur_mss);

	/* Some Solaris stacks overoptimize and ignore the FIN on a
	 * retransmit when old data is attached.  So strip it off
	 * since it is cheap to do so and saves bytes on the network.
	 */
	if (skb->len > 0 &&
	    (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) &&
	    tp->snd_una == (TCP_SKB_CB(skb)->end_seq - 1)) {
		if (!pskb_trim(skb, 0)) {
			/* Reuse, even though it does some unnecessary work */
			tcp_init_nondata_skb(skb, TCP_SKB_CB(skb)->end_seq - 1,
					     TCP_SKB_CB(skb)->tcp_flags);
			skb->ip_summed = CHECKSUM_NONE;
		}
	}

	/* Make a copy, if the first transmission SKB clone we made
	 * is still in somebody's hands, else make a clone.
	 */
	TCP_SKB_CB(skb)->when = tcp_time_stamp;

	/* make sure skb->data is aligned on arches that require it
	 * and check if ack-trimming & collapsing extended the headroom
	 * beyond what csum_start can cover.
	 */
	if (unlikely((NET_IP_ALIGN && ((unsigned long)skb->data & 3)) ||
		     skb_headroom(skb) >= 0xFFFF)) {
		struct sk_buff *nskb = __pskb_copy(skb, MAX_TCP_HEADER,
						   GFP_ATOMIC);
		return nskb ? tcp_transmit_skb(sk, nskb, 0, GFP_ATOMIC) :
			      -ENOBUFS;
	} else {
		return tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
	}
}

/* 重传一个skb */
int tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int err = __tcp_retransmit_skb(sk, skb);

	if (err == 0) {
		/* Update global TCP statistics. */
        /* 如果重传成功，则更新计数器 */
		TCP_INC_STATS(sock_net(sk), TCP_MIB_RETRANSSEGS);

		tp->total_retrans++;

#if FASTRETRANS_DEBUG > 0
		if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS) {
			net_dbg_ratelimited("retrans_out leaked\n");
		}
#endif
		if (!tp->retrans_out)
			tp->lost_retrans_low = tp->snd_nxt;
		TCP_SKB_CB(skb)->sacked |= TCPCB_RETRANS;
		tp->retrans_out += tcp_skb_pcount(skb);

		/* Save stamp of the first retransmit. */
        /* 记录最近一次重传开始的时间，不包括SYN包
         * 为什么要强调是最近一次重传？ 因为一次重传结束后，该值会被重置为0
         * 因此原始的英文注释是不准确的 */
		if (!tp->retrans_stamp)
			tp->retrans_stamp = TCP_SKB_CB(skb)->when;

        /* 记录用于推断出unnecessary retransmission需要的DSACK数量 */
		tp->undo_retrans += tcp_skb_pcount(skb);

		/* snd_nxt is stored to detect loss of retransmitted segment,
		 * see tcp_input.c tcp_sacktag_write_queue().
		 */
		TCP_SKB_CB(skb)->ack_seq = tp->snd_nxt;
	}
	return err;
}

/* Check if we forward retransmits are possible in the current
 * window/congestion state.
 */
/* 判断是否可以forward retrans */
static bool tcp_can_forward_retransmit(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Forward retransmissions are possible only during Recovery. */
    /* 只有在Recovery 状态下才能forward retrans */
	if (icsk->icsk_ca_state != TCP_CA_Recovery)
		return false;

	/* No forward retransmissions in Reno are possible. */
    /* Reno不支持SACK选项，所以也不允许fwd retrans */
	if (tcp_is_reno(tp))
		return false;

	/* Yeah, we have to make difficult choice between forward transmission
	 * and retransmission... Both ways have their merits...
	 *
	 * For now we do not retransmit anything, while we have some new
	 * segments to send. In the other cases, follow rule 3 for
	 * NextSeg() specified in RFC3517.
	 */
    /* 如果能发送新数据，也不执行fwd retrans */
	if (tcp_may_send_now(sk))
		return false;

	return true;
}

/* This gets called after a retransmit timeout, and the initially
 * retransmitted data is acknowledged.  It tries to continue
 * resending the rest of the retransmit queue, until either
 * we've sent it all or the congestion window limit is reached.
 * If doing SACK, the first ACK which comes back for a timeout
 * based retransmit packet might feed us FACK information again.
 * If so, we use it to avoid unnecessarily retransmissions.
 */
/* 该函数负责遍历重传队列，决定哪个SKB需要重传
 * 1. 首先重传标记为TCPCB_LOST的skb
 * 2. 之后可能还会重传：已发送的，但尚未收到确认的包(向前重传)
 *
 * 英文注释应该是不准确的，该函数不仅仅是在timeout之后会调用。在Recovery阶段也会调用
 */
void tcp_xmit_retransmit_queue(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	struct sk_buff *hole = NULL;
	u32 last_lost;
	int mib_idx;
	int fwd_rexmitting = 0;

    /* 如果没有未确认的数据包，则直接返回 */
	if (!tp->packets_out)
		return;

    /* 如果没有被标记为TCPCB_LOST的SKB，则将retransmit_high复位至snd_una */
	if (!tp->lost_out)
		tp->retransmit_high = tp->snd_una;

    /* 如果设置过需要重传的起始包，则从这个数据包开始遍历重传队列 */
	if (tp->retransmit_skb_hint) {
		skb = tp->retransmit_skb_hint;
		last_lost = TCP_SKB_CB(skb)->end_seq;
        /* 开启遍历重传队列时，last_lost不能超过retransmit_high */
		if (after(last_lost, tp->retransmit_high))
			last_lost = tp->retransmit_high;
	} else {
        /* 否则从第一个数据包开始遍历重传队列 */
        /* 走这个分支的典型场景： RTO后，retransmit_skb_hint被清除 */
		skb = tcp_write_queue_head(sk);
		last_lost = tp->snd_una;
	}

    /* 从上面确定的skb处开始遍历重传队列 */
	tcp_for_write_queue_from(skb, sk) {
        /* 获取该skb的SACK/FACK标记信息 */
		__u8 sacked = TCP_SKB_CB(skb)->sacked;

        /* 最多只能遍历到snd_nxt，也就是send head */
		if (skb == tcp_send_head(sk))
			break;
		/* we could do better than to assign each time */
        /* hole初始值为NULL，所以retransmit_skb_hint会默认指向进入循环时遍历的第一个SKB */
        /* hole为空的场景:
         * 1. hole默认为空，如果重传队列的起始几个SKB都不是hole，那么retransmit_skb_hint也会在每次循环是更新
         * 2. 在刚启用fwd时，如果需要hole不为空，则从hole位置开始fwd retrans，同时hole也会设置为空
         *    进而在所有被fwd retrans的SKB，都是满足hole为NULL，从而retransmit_skb_hint会指向最后一个被 fwd retrans的数据包 */
		if (hole == NULL)
			tp->retransmit_skb_hint = skb;

		/* Assume this retransmit will generate
		 * only one packet for congestion window
		 * calculation purposes.  This works because
		 * tcp_retransmit_skb() will chop up the
		 * packet to be MSS sized and all the
		 * packet counting works out.
		 */
        /* 如果pkts inflight超过了cwnd，则停止重传 */
		if (tcp_packets_in_flight(tp) >= tp->snd_cwnd)
			return;

        /* 默认情况是不启用forward retrans的，后续会看什么情况下会触发forward retrans */
		if (fwd_rexmitting) {
begin_fwd:
            /* 即使启用fwd retrans, 最大的允许范围也就是[retransmit_high, highest sack seq] */
			if (!before(TCP_SKB_CB(skb)->seq, tcp_highest_sack_seq(tp)))
				break;
			mib_idx = LINUX_MIB_TCPFORWARDRETRANS;

        /* 如果遍历到了retransmit_high，则需要看看是否可以执行forward retrans了 */
		} else if (!before(TCP_SKB_CB(skb)->seq, tp->retransmit_high)) {
            /* 更新retransmit_high为标记为TCPCB_LOST的最大序号 */
			tp->retransmit_high = last_lost;
            /* 判断是否允许fwd retrans，只有以下条件均成立时，才会触发forward retrans 
             * 1. 处于Recovery阶段
             * 2. 不是Reno算法，即支持SACK选项
             * 3. 没有新数据可以发送 */
			if (!tcp_can_forward_retransmit(sk))
				break;
			/* Backtrack if necessary to non-L'ed skb */
			if (hole != NULL) {
				skb = hole;
				hole = NULL;
			}
			fwd_rexmitting = 1;
			goto begin_fwd;

        /* 如果SKB没有标记LOST标记，则不会被重传。继续遍历下一个SKB */
		} else if (!(sacked & TCPCB_LOST)) {
            /* 如果SKB没有重传过，也没有被SACK确认，则说明它正在等待被按序确认。
             * 也就是说，这个SKB是一个空洞需要被按序确认掉，所以用hole指向它 */
            /* hole功能：在启用fwd retrans后，记录从哪个地方开始fwd retrans */
			if (hole == NULL && !(sacked & (TCPCB_SACKED_RETRANS|TCPCB_SACKED_ACKED)))
				hole = skb;
			continue;

		} else {
            /* 执行这条分支说明: SKB被标记为了TCPCB_LOST标记，所以需要重传 */
            /* last_lost每次都更新，最终的结果就是：last_lost记录最大lost序号 */
			last_lost = TCP_SKB_CB(skb)->end_seq;
			if (icsk->icsk_ca_state != TCP_CA_Loss)
                /* 快速重传"成功"次数*/
				mib_idx = LINUX_MIB_TCPFASTRETRANS;
			else
                /* 超时之后，在慢启动阶段"成功"重传次数 */
				mib_idx = LINUX_MIB_TCPSLOWSTARTRETRANS;
		}

        /* 如果该SKB已经被SACK确认过，或者已经重传了, 则继续遍历下一个SKB */
        /* TODO-DONE: 这个为什么需要判断TCPCB_SACKED_RETRANS标记 ?
         * 因为如果启用了fwd retrans，遍历的位置可能会回退到hole位置, 所以遍历时可能遇到刚刚已经重传过了的SKB */
		if (sacked & (TCPCB_SACKED_ACKED|TCPCB_SACKED_RETRANS))
			continue;

        /* 如果重传失败，则增加retrans fail计数器；
         * 否则根据重传类型，增加对应计数器： 快速重传 或者是 超时之后的慢启动重传 */
		if (tcp_retransmit_skb(sk, skb)) {
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPRETRANSFAIL);
			return;
		}
		NET_INC_STATS_BH(sock_net(sk), mib_idx);

        /* 如果处于CWR或Recovery阶段，则更新PRR算法发送出的数据包个数 */
		if (tcp_in_cwnd_reduction(sk))
			tp->prr_out += tcp_skb_pcount(skb);

        /* 如果是从重传队列的第一个SKB处开始遍历的，则需要重新设置RTO timer */
        /* 因为RTO后，retrans hint会被清除。所以如果下式成立，说明这是RTO超时后调用了该函数，所以需要重设RTO timer */
		if (skb == tcp_write_queue_head(sk))
			inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
						  inet_csk(sk)->icsk_rto,
						  TCP_RTO_MAX);
	}
}

/* Send a fin.  The caller locks the socket for us.  This cannot be
 * allowed to fail queueing a FIN frame under any circumstances.
 */
void tcp_send_fin(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = tcp_write_queue_tail(sk);
	int mss_now;

	/* Optimization, tack on the FIN if we have a queue of
	 * unsent frames.  But be careful about outgoing SACKS
	 * and IP options.
	 */
	mss_now = tcp_current_mss(sk);

	if (tcp_send_head(sk) != NULL) {
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_FIN;
		TCP_SKB_CB(skb)->end_seq++;
		tp->write_seq++;
	} else {
		/* Socket is locked, keep trying until memory is available. */
		for (;;) {
			skb = alloc_skb_fclone(MAX_TCP_HEADER,
					       sk->sk_allocation);
			if (skb)
				break;
			yield();
		}

		/* Reserve space for headers and prepare control bits. */
		skb_reserve(skb, MAX_TCP_HEADER);
		/* FIN eats a sequence byte, write_seq advanced by tcp_queue_skb(). */
		tcp_init_nondata_skb(skb, tp->write_seq,
				     TCPHDR_ACK | TCPHDR_FIN);
		tcp_queue_skb(sk, skb);
	}
	__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_OFF);
}

/* We get here when a process closes a file descriptor (either due to
 * an explicit close() or as a byproduct of exit()'ing) and there
 * was unread data in the receive queue.  This behavior is recommended
 * by RFC 2525, section 2.17.  -DaveM
 */
/* 主动的发送一个reset包给对端 */
void tcp_send_active_reset(struct sock *sk, gfp_t priority)
{
	struct sk_buff *skb;

	/* NOTE: No TCP options attached and we never retransmit this. */
	skb = alloc_skb(MAX_TCP_HEADER, priority);
	if (!skb) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTFAILED);
		return;
	}

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	tcp_init_nondata_skb(skb, tcp_acceptable_seq(sk),
			     TCPHDR_ACK | TCPHDR_RST);
	/* Send it off. */
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	if (tcp_transmit_skb(sk, skb, 0, priority))
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTFAILED);

	TCP_INC_STATS(sock_net(sk), TCP_MIB_OUTRSTS);
}

/* Send a crossed SYN-ACK during socket establishment.
 * WARNING: This routine must only be called when we have already sent
 * a SYN packet that crossed the incoming SYN that caused this routine
 * to get called. If this assumption fails then the initial rcv_wnd
 * and rcv_wscale values will not be correct.
 */
int tcp_send_synack(struct sock *sk)
{
	struct sk_buff *skb;

	skb = tcp_write_queue_head(sk);
	if (skb == NULL || !(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)) {
		pr_debug("%s: wrong queue state\n", __func__);
		return -EFAULT;
	}
	if (!(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_ACK)) {
		if (skb_cloned(skb)) {
			struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);
			if (nskb == NULL)
				return -ENOMEM;
			tcp_unlink_write_queue(skb, sk);
			skb_header_release(nskb);
			__tcp_add_write_queue_head(sk, nskb);
			sk_wmem_free_skb(sk, skb);
			sk->sk_wmem_queued += nskb->truesize;
			sk_mem_charge(sk, nskb->truesize);
			skb = nskb;
		}

		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_ACK;
		TCP_ECN_send_synack(tcp_sk(sk), skb);
	}
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	return tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
}

/**
 * tcp_make_synack - Prepare a SYN-ACK.
 * sk: listener socket
 * dst: dst entry attached to the SYNACK
 * req: request_sock pointer
 *
 * Allocate one skb and build a SYNACK packet.
 * @dst is consumed : Caller should not use it again.
 */
/* 返回一个被构造一个syn/ack包 */
struct sk_buff *tcp_make_synack(struct sock *sk, struct dst_entry *dst,
				struct request_sock *req,
				struct tcp_fastopen_cookie *foc)
{
	struct tcp_out_options opts;
	struct inet_request_sock *ireq = inet_rsk(req);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcphdr *th;
	struct sk_buff *skb;
	struct tcp_md5sig_key *md5;
	int tcp_header_size;
	int mss;

    /* 分配一个skb的内存空间 */
	skb = alloc_skb(MAX_TCP_HEADER + 15, sk_gfp_atomic(sk, GFP_ATOMIC));
	if (unlikely(!skb)) {
		dst_release(dst);
		return NULL;
	}
	/* Reserve space for headers. */
	skb_reserve(skb, MAX_TCP_HEADER);

	skb_dst_set(skb, dst);
	security_skb_owned_by(skb, sk);

	mss = dst_metric_advmss(dst);
	if (tp->rx_opt.user_mss && tp->rx_opt.user_mss < mss)
		mss = tp->rx_opt.user_mss;

	if (req->rcv_wnd == 0) { /* ignored for retransmitted syns */
		__u8 rcv_wscale;
		/* Set this up on the first call only */
		req->window_clamp = tp->window_clamp ? : dst_metric(dst, RTAX_WINDOW);

		/* limit the window selection if the user enforce a smaller rx buffer */
		if (sk->sk_userlocks & SOCK_RCVBUF_LOCK &&
		    (req->window_clamp > tcp_full_space(sk) || req->window_clamp == 0))
			req->window_clamp = tcp_full_space(sk);

		/* tcp_full_space because it is guaranteed to be the first packet */
		tcp_select_initial_window(tcp_full_space(sk),
			mss - (ireq->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0),
			&req->rcv_wnd,
			&req->window_clamp,
			ireq->wscale_ok,
			&rcv_wscale,
			dst_metric(dst, RTAX_INITRWND));
		ireq->rcv_wscale = rcv_wscale;
	}

	memset(&opts, 0, sizeof(opts));
#ifdef CONFIG_SYN_COOKIES
	if (unlikely(req->cookie_ts))
		TCP_SKB_CB(skb)->when = cookie_init_timestamp(req);
	else
#endif
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	tcp_header_size = tcp_synack_options(sk, req, mss, skb, &opts, &md5,
					     foc) + sizeof(*th);

	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);

	th = tcp_hdr(skb);
	memset(th, 0, sizeof(struct tcphdr));
	th->syn = 1;
	th->ack = 1;
	TCP_ECN_make_synack(req, th);
	th->source = ireq->loc_port;
	th->dest = ireq->rmt_port;
	/* Setting of flags are superfluous here for callers (and ECE is
	 * not even correctly set)
	 */
	tcp_init_nondata_skb(skb, tcp_rsk(req)->snt_isn,
			     TCPHDR_SYN | TCPHDR_ACK);

	th->seq = htonl(TCP_SKB_CB(skb)->seq);
	/* XXX data is queued and acked as is. No buffer/window check */
	th->ack_seq = htonl(tcp_rsk(req)->rcv_nxt);

	/* RFC1323: The window in SYN & SYN/ACK segments is never scaled. */
	th->window = htons(min(req->rcv_wnd, 65535U));
	tcp_options_write((__be32 *)(th + 1), tp, &opts);
	th->doff = (tcp_header_size >> 2);
    /* 这里应该可以根据dst路由来发现ifindex */
	TCP_ADD_STATS(sock_net(sk), TCP_MIB_OUTSEGS, tcp_skb_pcount(skb));

#ifdef CONFIG_TCP_MD5SIG
	/* Okay, we have all we need - do the md5 hash if needed */
	if (md5) {
		tcp_rsk(req)->af_specific->calc_md5_hash(opts.hash_location,
					       md5, NULL, req, skb);
	}
#endif

	return skb;
}
EXPORT_SYMBOL(tcp_make_synack);

/* Do all connect socket setups that can be done AF independent. */
/* 完成诸多tp connect时的初始化动作，如SYN包中的awnd大小，snd_una, snd_nxt */
void tcp_connect_init(struct sock *sk)
{
	const struct dst_entry *dst = __sk_dst_get(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	__u8 rcv_wscale;

	/* We'll fix this up when we get a response from the other end.
	 * See tcp_input.c:tcp_rcv_state_process case TCP_SYN_SENT.
	 */
	tp->tcp_header_len = sizeof(struct tcphdr) +
		(sysctl_tcp_timestamps ? TCPOLEN_TSTAMP_ALIGNED : 0);

#ifdef CONFIG_TCP_MD5SIG
	if (tp->af_specific->md5_lookup(sk, sk) != NULL)
		tp->tcp_header_len += TCPOLEN_MD5SIG_ALIGNED;
#endif

	/* If user gave his TCP_MAXSEG, record it to clamp */
	if (tp->rx_opt.user_mss)
		tp->rx_opt.mss_clamp = tp->rx_opt.user_mss;
	tp->max_window = 0;
	tcp_mtup_init(sk);
	tcp_sync_mss(sk, dst_mtu(dst));

	if (!tp->window_clamp)
		tp->window_clamp = dst_metric(dst, RTAX_WINDOW);
	tp->advmss = dst_metric_advmss(dst);
	if (tp->rx_opt.user_mss && tp->rx_opt.user_mss < tp->advmss)
		tp->advmss = tp->rx_opt.user_mss;

	tcp_initialize_rcv_mss(sk);

	/* limit the window selection if the user enforce a smaller rx buffer */
	if (sk->sk_userlocks & SOCK_RCVBUF_LOCK &&
	    (tp->window_clamp > tcp_full_space(sk) || tp->window_clamp == 0))
		tp->window_clamp = tcp_full_space(sk);

    /* TODO: 确定第一个awnd */
	tcp_select_initial_window(tcp_full_space(sk),
				  tp->advmss - (tp->rx_opt.ts_recent_stamp ? tp->tcp_header_len - sizeof(struct tcphdr) : 0),
				  &tp->rcv_wnd,
				  &tp->window_clamp,
				  sysctl_tcp_window_scaling,
				  &rcv_wscale,
				  dst_metric(dst, RTAX_INITRWND));

	tp->rx_opt.rcv_wscale = rcv_wscale;
	tp->rcv_ssthresh = tp->rcv_wnd;

	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->snd_wnd = 0;
	tcp_init_wl(tp, 0);
	tp->snd_una = tp->write_seq;
	tp->snd_sml = tp->write_seq;
	tp->snd_up = tp->write_seq;
	tp->snd_nxt = tp->write_seq;

	if (likely(!tp->repair))
		tp->rcv_nxt = 0;
	tp->rcv_wup = tp->rcv_nxt;
	tp->copied_seq = tp->rcv_nxt;

	inet_csk(sk)->icsk_rto = TCP_TIMEOUT_INIT;
	inet_csk(sk)->icsk_retransmits = 0;
	tcp_clear_retrans(tp);
}

/* 将skb挂到 write queue中去 */
static void tcp_connect_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

	tcb->end_seq += skb->len;
	skb_header_release(skb);
	__tcp_add_write_queue_tail(sk, skb);
    /* truesize包括： skb struct size + skb data */
	sk->sk_wmem_queued += skb->truesize;    /* sk_wmem_queued记录write queue中分配了多少内存 */
	sk_mem_charge(sk, skb->truesize);       /* 将forward alloc的空间减去skb的truesize */
	tp->write_seq = tcb->end_seq;
	tp->packets_out += tcp_skb_pcount(skb);
}

/* Build and send a SYN with data and (cached) Fast Open cookie. However,
 * queue a data-only packet after the regular SYN, such that regular SYNs
 * are retransmitted on timeouts. Also if the remote SYN-ACK acknowledges
 * only the SYN sequence, the data are retransmitted in the first ACK.
 * If cookie is not cached or other error occurs, falls back to send a
 * regular SYN with Fast Open cookie request option.
 */
static int tcp_send_syn_data(struct sock *sk, struct sk_buff *syn)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_fastopen_request *fo = tp->fastopen_req;
	int syn_loss = 0, space, i, err = 0, iovlen = fo->data->msg_iovlen;
	struct sk_buff *syn_data = NULL, *data;
	unsigned long last_syn_loss = 0;

	tp->rx_opt.mss_clamp = tp->advmss;  /* If MSS is not cached */
	tcp_fastopen_cache_get(sk, &tp->rx_opt.mss_clamp, &fo->cookie,
			       &syn_loss, &last_syn_loss);
	/* Recurring FO SYN losses: revert to regular handshake temporarily */
	if (syn_loss > 1 &&
	    time_before(jiffies, last_syn_loss + (60*HZ << syn_loss))) {
		fo->cookie.len = -1;
		goto fallback;
	}

	if (sysctl_tcp_fastopen & TFO_CLIENT_NO_COOKIE)
		fo->cookie.len = -1;
	else if (fo->cookie.len <= 0)
		goto fallback;

	/* MSS for SYN-data is based on cached MSS and bounded by PMTU and
	 * user-MSS. Reserve maximum option space for middleboxes that add
	 * private TCP options. The cost is reduced data space in SYN :(
	 */
	if (tp->rx_opt.user_mss && tp->rx_opt.user_mss < tp->rx_opt.mss_clamp)
		tp->rx_opt.mss_clamp = tp->rx_opt.user_mss;
	space = __tcp_mtu_to_mss(sk, inet_csk(sk)->icsk_pmtu_cookie) -
		MAX_TCP_OPTION_SPACE;

	syn_data = skb_copy_expand(syn, skb_headroom(syn), space,
				   sk->sk_allocation);
	if (syn_data == NULL)
		goto fallback;

	for (i = 0; i < iovlen && syn_data->len < space; ++i) {
		struct iovec *iov = &fo->data->msg_iov[i];
		unsigned char __user *from = iov->iov_base;
		int len = iov->iov_len;

		if (syn_data->len + len > space)
			len = space - syn_data->len;
		else if (i + 1 == iovlen)
			/* No more data pending in inet_wait_for_connect() */
			fo->data = NULL;

		if (skb_add_data(syn_data, from, len))
			goto fallback;
	}

	/* Queue a data-only packet after the regular SYN for retransmission */
	data = pskb_copy(syn_data, sk->sk_allocation);
	if (data == NULL)
		goto fallback;
	TCP_SKB_CB(data)->seq++;
	TCP_SKB_CB(data)->tcp_flags &= ~TCPHDR_SYN;
	TCP_SKB_CB(data)->tcp_flags = (TCPHDR_ACK|TCPHDR_PSH);
	tcp_connect_queue_skb(sk, data);
	fo->copied = data->len;

	if (tcp_transmit_skb(sk, syn_data, 0, sk->sk_allocation) == 0) {
		tp->syn_data = (fo->copied > 0);
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPFASTOPENACTIVE);
		goto done;
	}
	syn_data = NULL;

fallback:
	/* Send a regular SYN with Fast Open cookie request option */
	if (fo->cookie.len > 0)
		fo->cookie.len = 0;
	err = tcp_transmit_skb(sk, syn, 1, sk->sk_allocation);
	if (err)
		tp->syn_fastopen = 0;
	kfree_skb(syn_data);
done:
	fo->cookie.len = -1;  /* Exclude Fast Open option for SYN retries */
	return err;
}

/* Build a SYN and send it off. */
/* 发送第一个SYN包 */
int tcp_connect(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int err;

    /* 准备工作 */
	tcp_connect_init(sk);

	if (unlikely(tp->repair)) {
		tcp_finish_connect(sk, NULL);
		return 0;
	}

    /* 分配 skb */
	buff = alloc_skb_fclone(MAX_TCP_HEADER + 15, sk->sk_allocation);
	if (unlikely(buff == NULL))
		return -ENOBUFS;

	/* Reserve space for headers. */
    /* 预留TCP、IP Link Layer的header空间 */
	skb_reserve(buff, MAX_TCP_HEADER);

	tcp_init_nondata_skb(buff, tp->write_seq++, TCPHDR_SYN);
    /* 记录发送SYN包的时间 */
	tp->retrans_stamp = TCP_SKB_CB(buff)->when = tcp_time_stamp;
    /* 将buff挂到sk的write queue中 */
	tcp_connect_queue_skb(sk, buff);
	TCP_ECN_send_syn(sk, buff);

	/* Send off SYN; include data in Fast Open. */
	err = tp->fastopen_req ? tcp_send_syn_data(sk, buff) :
	      tcp_transmit_skb(sk, buff, 1, sk->sk_allocation);
	if (err == -ECONNREFUSED)
		return err;

	/* We change tp->snd_nxt after the tcp_transmit_skb() call
	 * in order to make this packet get counted in tcpOutSegs.
	 */
	tp->snd_nxt = tp->write_seq;
	tp->pushed_seq = tp->write_seq;
	TCP_INC_STATS(sock_net(sk), TCP_MIB_ACTIVEOPENS);

	/* Timer for repeating the SYN until an answer. */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
	return 0;
}
EXPORT_SYMBOL(tcp_connect);

/* Send out a delayed ack, the caller does the policy checking
 * to see if we should even be here.  See tcp_input.c:tcp_ack_snd_check()
 * for details.
 */
void tcp_send_delayed_ack(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int ato = icsk->icsk_ack.ato;
	unsigned long timeout;

    /* 这一段的目的就是通过各种手段来降低ato的值，避免ato过大
     * ato过大的可能原因之一就是执行过inflate ATO相关代码 */
	if (ato > TCP_DELACK_MIN) {
		const struct tcp_sock *tp = tcp_sk(sk);
		int max_ato = HZ / 2;   /* 500ms */

        /* 如果处于pingpong状态(数据有来有往), 
         * 或者设置了ICSK_ACK_PUSHED标志的话 */
		if (icsk->icsk_ack.pingpong ||
		    (icsk->icsk_ack.pending & ICSK_ACK_PUSHED))
			max_ato = TCP_DELACK_MAX;   /* 200ms */

		/* Slow path, intersegment interval is "high". */

		/* If some rtt estimate is known, use it to bound delayed ack.
		 * Do not use inet_csk(sk)->icsk_rto here, use results of rtt measurements
		 * directly.
		 */
		if (tp->srtt) {
			int rtt = max(tp->srtt >> 3, TCP_DELACK_MIN);

			if (rtt < max_ato)
				max_ato = rtt;
		}

		ato = min(ato, max_ato);
	}

	/* Stay within the limit we were given */
	timeout = jiffies + ato;    /* 延迟确认定时器的超时时刻 */

	/* Use new timeout only if there wasn't a older one earlier. */
	if (icsk->icsk_ack.pending & ICSK_ACK_TIMER) {
		/* If delack timer was blocked or is about to expire,
		 * send ACK now.
		 */
		if (icsk->icsk_ack.blocked ||
		    time_before_eq(icsk->icsk_ack.timeout, jiffies + (ato >> 2))) {
			tcp_send_ack(sk);
			return;
		}

        /* 如果timeout值比之前设置的timeout值还小，则用之前的timeout */
		if (!time_before(timeout, icsk->icsk_ack.timeout))
			timeout = icsk->icsk_ack.timeout;
	}
    /* 设置ACK需要发送标志、定时器启动标志 */
	icsk->icsk_ack.pending |= ICSK_ACK_SCHED | ICSK_ACK_TIMER;
	icsk->icsk_ack.timeout = timeout;
	sk_reset_timer(sk, &icsk->icsk_delack_timer, timeout);
}

/* This routine sends an ack and also updates the window. */
/* 发送一个ACK包 */
void tcp_send_ack(struct sock *sk)
{
	struct sk_buff *buff;

	/* If we have been reset, we may not send again. */
	if (sk->sk_state == TCP_CLOSE)
		return;

	/* We are not putting this on the write queue, so
	 * tcp_transmit_skb() will set the ownership to this
	 * sock.
	 */
	buff = alloc_skb(MAX_TCP_HEADER, sk_gfp_atomic(sk, GFP_ATOMIC));
	if (buff == NULL) {
        /* skb结构无法分配成功，则首先标记有一个要发送的ACK在等待schedule */
		inet_csk_schedule_ack(sk);
        /* 接着启动延迟确认计时器, 此时超时时间为TCP_DELACK_MAX(200ms) */
		inet_csk(sk)->icsk_ack.ato = TCP_ATO_MIN;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_DACK,
					  TCP_DELACK_MAX, TCP_RTO_MAX);
		return;
	}

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(buff, MAX_TCP_HEADER);
	tcp_init_nondata_skb(buff, tcp_acceptable_seq(sk), TCPHDR_ACK);

	/* Send it off, this clears delayed acks for us. */
	TCP_SKB_CB(buff)->when = tcp_time_stamp;
	tcp_transmit_skb(sk, buff, 0, sk_gfp_atomic(sk, GFP_ATOMIC));
}

/* This routine sends a packet with an out of date sequence
 * number. It assumes the other end will try to ack it.
 *
 * Question: what should we make while urgent mode?
 * 4.4BSD forces sending single byte of data. We cannot send
 * out of window data, because we have SND.NXT==SND.MAX...
 *
 * Current solution: to send TWO zero-length segments in urgent mode:
 * one is with SEG.SEQ=SND.UNA to deliver urgent pointer, another is
 * out-of-date with SND.UNA-1 to probe window.
 */
/* 发送一个字节的数据包进行zero window probe */
static int tcp_xmit_probe_skb(struct sock *sk, int urgent)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	/* We don't queue it, tcp_transmit_skb() sets ownership. */
	skb = alloc_skb(MAX_TCP_HEADER, sk_gfp_atomic(sk, GFP_ATOMIC));
	if (skb == NULL)
		return -1;

	/* Reserve space for headers and set control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	/* Use a previous sequence.  This should cause the other
	 * end to send an ack.  Don't queue or clone SKB, just
	 * send it.
	 */
	tcp_init_nondata_skb(skb, tp->snd_una - !urgent, TCPHDR_ACK);
	TCP_SKB_CB(skb)->when = tcp_time_stamp;     /* 记录skb的发送时间 */
	return tcp_transmit_skb(sk, skb, 0, GFP_ATOMIC);
}

void tcp_send_window_probe(struct sock *sk)
{
	if (sk->sk_state == TCP_ESTABLISHED) {
		tcp_sk(sk)->snd_wl1 = tcp_sk(sk)->rcv_nxt - 1;
		tcp_sk(sk)->snd_nxt = tcp_sk(sk)->write_seq;
		tcp_xmit_probe_skb(sk, 0);
	}
}

/* Initiate keepalive or window probe from timer. */
/* keepalive和zero window probe会调用该函数
 * 功能： checks if the receiver has advertised enough window to transmit new data
 *        and transmits the new segment if permitted. */
int tcp_write_wakeup(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	if (sk->sk_state == TCP_CLOSE)
		return -1;

    /* 如果有数据等待发送，并且对端的接收窗口允许发送哪怕一个字节的数据 */
	if ((skb = tcp_send_head(sk)) != NULL &&
	    before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp))) {
		int err;
		unsigned int mss = tcp_current_mss(sk);
		unsigned int seg_size = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

		if (before(tp->pushed_seq, TCP_SKB_CB(skb)->end_seq))
			tp->pushed_seq = TCP_SKB_CB(skb)->end_seq;

		/* We are probing the opening of a window
		 * but the window size is != 0
		 * must have been a result SWS avoidance ( sender )
		 */
        /* 如果接收窗口不够一个SKB中的数据，则需要TCP层进行分片 */
		if (seg_size < TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq ||
		    skb->len > mss) {
			seg_size = min(seg_size, mss);
			TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_PSH;
			if (tcp_fragment(sk, skb, seg_size, mss))
				return -1;
		} else if (!tcp_skb_pcount(skb))
			tcp_set_skb_tso_segs(sk, skb, mss);

		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_PSH;
		TCP_SKB_CB(skb)->when = tcp_time_stamp;
		err = tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
		if (!err)
			tcp_event_new_data_sent(sk, skb);
		return err;
	} else {
        /* TODO: 这个判断条件为什么是urgent mode判断方法？ */
		if (between(tp->snd_up, tp->snd_una + 1, tp->snd_una + 0xFFFF))
			tcp_xmit_probe_skb(sk, 1);
        /* 如果接收窗口为0， 则发送一个字节的新数据进行zero window probe */
		return tcp_xmit_probe_skb(sk, 0);
	}
}

/* A window probe timeout has occurred.  If window is not closed send
 * a partial packet else a zero probe.
 */
/* 发送一个零窗口探测包 */
void tcp_send_probe0(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int err;

	err = tcp_write_wakeup(sk);

	if (tp->packets_out || !tcp_send_head(sk)) {
		/* Cancel probe timer, if it is not required. */
		icsk->icsk_probes_out = 0;
		icsk->icsk_backoff = 0;
		return;
	}

	if (err <= 0) {
		if (icsk->icsk_backoff < sysctl_tcp_retries2)
			icsk->icsk_backoff++;
		icsk->icsk_probes_out++;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
					  min(icsk->icsk_rto << icsk->icsk_backoff, TCP_RTO_MAX),
					  TCP_RTO_MAX);
	} else {
		/* If packet was not sent due to local congestion,
		 * do not backoff and do not remember icsk_probes_out.
		 * Let local senders to fight for local resources.
		 *
		 * Use accumulated backoff yet.
		 */
		if (!icsk->icsk_probes_out)
			icsk->icsk_probes_out = 1;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
					  min(icsk->icsk_rto << icsk->icsk_backoff,
					      TCP_RESOURCE_PROBE_INTERVAL),
					  TCP_RTO_MAX);
	}
}
