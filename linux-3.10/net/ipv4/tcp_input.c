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
 * Changes:
 *		Pedro Roque	:	Fast Retransmit/Recovery.
 *					Two receive queues.
 *					Retransmit queue handled by TCP.
 *					Better retransmit timer handling.
 *					New congestion avoidance.
 *					Header prediction.
 *					Variable renaming.
 *
 *		Eric		:	Fast Retransmit.
 *		Randy Scott	:	MSS option defines.
 *		Eric Schenk	:	Fixes to slow start algorithm.
 *		Eric Schenk	:	Yet another double ACK bug.
 *		Eric Schenk	:	Delayed ACK bug fixes.
 *		Eric Schenk	:	Floyd style fast retrans war avoidance.
 *		David S. Miller	:	Don't allow zero congestion window.
 *		Eric Schenk	:	Fix retransmitter so that it sends
 *					next packet on ack of previous packet.
 *		Andi Kleen	:	Moved open_request checking here
 *					and process RSTs for open_requests.
 *		Andi Kleen	:	Better prune_queue, and other fixes.
 *		Andrey Savochkin:	Fix RTT measurements in the presence of
 *					timestamps.
 *		Andrey Savochkin:	Check sequence numbers correctly when
 *					removing SACKs due to in sequence incoming
 *					data segments.
 *		Andi Kleen:		Make sure we never ack data there is not
 *					enough room for. Also make this condition
 *					a fatal error if it might still happen.
 *		Andi Kleen:		Add tcp_measure_rcv_mss to make
 *					connections with MSS<min(MTU,ann. MSS)
 *					work without delayed acks.
 *		Andi Kleen:		Process packets with PSH set in the
 *					fast path.
 *		J Hadi Salim:		ECN support
 *	 	Andrei Gurtov,
 *		Pasi Sarolahti,
 *		Panu Kuhlberg:		Experimental audit of TCP (re)transmission
 *					engine. Lots of bugs are found.
 *		Pasi Sarolahti:		F-RTO for dealing with spurious RTOs
 */

#define pr_fmt(fmt) "TCP: " fmt

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/kernel.h>
#include <net/dst.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/ipsec.h>
#include <asm/unaligned.h>
#include <net/netdma.h>

int sysctl_tcp_timestamps __read_mostly = 1;
int sysctl_tcp_window_scaling __read_mostly = 1;
int sysctl_tcp_sack __read_mostly = 1;
int sysctl_tcp_fack __read_mostly = 1;
int sysctl_tcp_reordering __read_mostly = TCP_FASTRETRANS_THRESH;
EXPORT_SYMBOL(sysctl_tcp_reordering);
int sysctl_tcp_dsack __read_mostly = 1;
int sysctl_tcp_app_win __read_mostly = 31;
int sysctl_tcp_adv_win_scale __read_mostly = 1;
EXPORT_SYMBOL(sysctl_tcp_adv_win_scale);

/* rfc5961 challenge ack rate limiting */
int sysctl_tcp_challenge_ack_limit = 100;

int sysctl_tcp_stdurg __read_mostly;
int sysctl_tcp_rfc1337 __read_mostly;
int sysctl_tcp_max_orphans __read_mostly = NR_FILE;
/* frto的出发点：更快的从spurious rto中恢复出来
 * TODO: frto机制已经跟undo机制混在一起了，需要抽空结合RFC仔细的理一下 */
int sysctl_tcp_frto __read_mostly = 2;

int sysctl_tcp_thin_dupack __read_mostly;

int sysctl_tcp_moderate_rcvbuf __read_mostly = 1;
int sysctl_tcp_early_retrans __read_mostly = 3;

#define FLAG_DATA		0x01 /* Incoming frame contained data.		*/
#define FLAG_WIN_UPDATE		0x02 /* Incoming ACK was a window update.	*/
#define FLAG_DATA_ACKED		0x04 /* This ACK acknowledged new data.		*/
#define FLAG_RETRANS_DATA_ACKED	0x08 /* "" "" some of which was retransmitted.	*/
#define FLAG_SYN_ACKED		0x10 /* This ACK acknowledged SYN.		*/
#define FLAG_DATA_SACKED	0x20 /* New SACK.				*/
#define FLAG_ECE		0x40 /* ECE in this ACK				*/
#define FLAG_SLOWPATH		0x100 /* Do not skip RFC checks for window update.*/
#define FLAG_ORIG_SACK_ACKED	0x200 /* Never retransmitted data are (s)acked	*/
/* TODO： 为什么FLAG_SND_UNA_ADVANCED不等于FLAG_DATA_ACKED ？ */
#define FLAG_SND_UNA_ADVANCED	0x400 /* Snd_una was changed (!= FLAG_DATA_ACKED) */
#define FLAG_DSACKING_ACK	0x800 /* SACK blocks contained D-SACK info */
#define FLAG_SACK_RENEGING	0x2000 /* snd_una advanced to a sacked seq */
#define FLAG_UPDATE_TS_RECENT	0x4000 /* tcp_replace_ts_recent() */

#define FLAG_ACKED		(FLAG_DATA_ACKED|FLAG_SYN_ACKED)
#define FLAG_NOT_DUP		(FLAG_DATA|FLAG_WIN_UPDATE|FLAG_ACKED)
#define FLAG_CA_ALERT		(FLAG_DATA_SACKED|FLAG_ECE)
#define FLAG_FORWARD_PROGRESS	(FLAG_ACKED|FLAG_DATA_SACKED)

#define TCP_REMNANT (TCP_FLAG_FIN|TCP_FLAG_URG|TCP_FLAG_SYN|TCP_FLAG_PSH)
#define TCP_HP_BITS (~(TCP_RESERVED_BITS|TCP_FLAG_PSH))

/* Adapt the MSS value used to make delayed ack decision to the
 * real world.
 */
/* 计算出receive mss，即the maximum length ot the TCP segment so far received. */
static void tcp_measure_rcv_mss(struct sock *sk, const struct sk_buff *skb)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const unsigned int lss = icsk->icsk_ack.last_seg_size;
	unsigned int len;

	icsk->icsk_ack.last_seg_size = 0;

	/* skb->len may jitter because of SACKs, even if peer
	 * sends good full-sized frames.
	 */
	len = skb_shinfo(skb)->gso_size ? : skb->len;
    /* 如果len更大，则更新rcv_mss */
	if (len >= icsk->icsk_ack.rcv_mss) {
		icsk->icsk_ack.rcv_mss = len;
	} else {
		/* Otherwise, we make more careful check taking into account,
		 * that SACKs block is variable.
		 *
		 * "len" is invariant segment length, including TCP header.
		 */
		len += skb->data - skb_transport_header(skb);
		if (len >= TCP_MSS_DEFAULT + sizeof(struct tcphdr) ||
            /* NOTE: 从下面一句话, 可以看出对于数据包，如果它不是full sized，则应该打上PUSH标记 */
		    /* If PSH is not set, packet should be
		     * full sized, provided peer TCP is not badly broken.
		     * This observation (if it is correct 8)) allows
		     * to handle super-low mtu links fairly.
		     */
		    (len >= TCP_MIN_MSS + sizeof(struct tcphdr) &&
		     !(tcp_flag_word(tcp_hdr(skb)) & TCP_REMNANT))) {
			/* Subtract also invariant (if peer is RFC compliant),
			 * tcp header plus fixed timestamp option length.
			 * Resulting "len" is MSS free of SACK jitter.
			 */
			len -= tcp_sk(sk)->tcp_header_len;
			icsk->icsk_ack.last_seg_size = len;
			if (len == lss) {
				icsk->icsk_ack.rcv_mss = len;
				return;
			}
		}
		if (icsk->icsk_ack.pending & ICSK_ACK_PUSHED)
			icsk->icsk_ack.pending |= ICSK_ACK_PUSHED2;
		icsk->icsk_ack.pending |= ICSK_ACK_PUSHED;
	}
}

static void tcp_incr_quickack(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	unsigned int quickacks = tcp_sk(sk)->rcv_wnd / (2 * icsk->icsk_ack.rcv_mss);

	if (quickacks == 0)
		quickacks = 2;
	if (quickacks > icsk->icsk_ack.quick)
		icsk->icsk_ack.quick = min(quickacks, TCP_MAX_QUICKACKS);
}

static void tcp_enter_quickack_mode(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	tcp_incr_quickack(sk);
	icsk->icsk_ack.pingpong = 0;
	icsk->icsk_ack.ato = TCP_ATO_MIN;
}

/* Send ACKs quickly, if "quick" count is not exhausted
 * and the session is not interactive.
 */
static inline bool tcp_in_quickack_mode(const struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	return icsk->icsk_ack.quick && !icsk->icsk_ack.pingpong;
}

static inline void TCP_ECN_queue_cwr(struct tcp_sock *tp)
{
	if (tp->ecn_flags & TCP_ECN_OK)
		tp->ecn_flags |= TCP_ECN_QUEUE_CWR;
}

/* 如果收到对端发送的带cwr标记的TCP包，则清除TCP_ECN_DEMAND_CWR标记 */
static inline void TCP_ECN_accept_cwr(struct tcp_sock *tp, const struct sk_buff *skb)
{
	if (tcp_hdr(skb)->cwr)
		tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
}

static inline void TCP_ECN_withdraw_cwr(struct tcp_sock *tp)
{
	tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
}

static inline void TCP_ECN_check_ce(struct tcp_sock *tp, const struct sk_buff *skb)
{
	if (!(tp->ecn_flags & TCP_ECN_OK))
		return;

	switch (TCP_SKB_CB(skb)->ip_dsfield & INET_ECN_MASK) {
	case INET_ECN_NOT_ECT:
		/* Funny extension: if ECT is not set on a segment,
		 * and we already seen ECT on a previous segment,
		 * it is probably a retransmit.
		 */
		if (tp->ecn_flags & TCP_ECN_SEEN)
			tcp_enter_quickack_mode((struct sock *)tp);
		break;
	case INET_ECN_CE:
		if (!(tp->ecn_flags & TCP_ECN_DEMAND_CWR)) {
			/* Better not delay acks, sender can have a very low cwnd */
			tcp_enter_quickack_mode((struct sock *)tp);
			tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
		}
		/* fallinto */
	default:
		tp->ecn_flags |= TCP_ECN_SEEN;
	}
}

static inline void TCP_ECN_rcv_synack(struct tcp_sock *tp, const struct tcphdr *th)
{
	if ((tp->ecn_flags & TCP_ECN_OK) && (!th->ece || th->cwr))
		tp->ecn_flags &= ~TCP_ECN_OK;
}

static inline void TCP_ECN_rcv_syn(struct tcp_sock *tp, const struct tcphdr *th)
{
	if ((tp->ecn_flags & TCP_ECN_OK) && (!th->ece || !th->cwr))
		tp->ecn_flags &= ~TCP_ECN_OK;
}

/* 判断是否收到了显示拥塞通知 */
static bool TCP_ECN_rcv_ecn_echo(const struct tcp_sock *tp, const struct tcphdr *th)
{
	if (th->ece && !th->syn && (tp->ecn_flags & TCP_ECN_OK))
		return true;
	return false;
}

/* Buffer size and advertised window tuning.
 *
 * 1. Tuning sk->sk_sndbuf, when connection enters established state.
 */

static void tcp_fixup_sndbuf(struct sock *sk)
{
	int sndmem = SKB_TRUESIZE(tcp_sk(sk)->rx_opt.mss_clamp + MAX_TCP_HEADER);

	sndmem *= TCP_INIT_CWND;
	if (sk->sk_sndbuf < sndmem)
		sk->sk_sndbuf = min(sndmem, sysctl_tcp_wmem[2]);
}

/* 2. Tuning advertised window (window_clamp, rcv_ssthresh)
 *
 * All tcp_full_space() is split to two parts: "network" buffer, allocated
 * forward and advertised in receiver window (tp->rcv_wnd) and
 * "application buffer", required to isolate scheduling/application
 * latencies from network.
 * window_clamp is maximal advertised window. It can be less than
 * tcp_full_space(), in this case tcp_full_space() - window_clamp
 * is reserved for "application" buffer. The less window_clamp is
 * the smoother our behaviour from viewpoint of network, but the lower
 * throughput and the higher sensitivity of the connection to losses. 8)
 *
 * rcv_ssthresh is more strict window_clamp used at "slow start"
 * phase to predict further behaviour of this connection.
 * It is used for two goals:
 * - to enforce header prediction at sender, even when application
 *   requires some significant "application buffer". It is check #1.
 * - to prevent pruning of receive queue because of misprediction
 *   of receiver window. Check #2.
 *
 * The scheme does not work when sender sends good segments opening
 * window and then starts to feed us spaghetti. But it should work
 * in common situations. Otherwise, we have to rely on queue collapsing.
 */

/* Slow part of check#2. */
static int __tcp_grow_window(const struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	/* Optimize this! */
	int truesize = tcp_win_from_space(skb->truesize) >> 1;
	int window = tcp_win_from_space(sysctl_tcp_rmem[2]) >> 1;

	while (tp->rcv_ssthresh <= window) {
		if (truesize <= skb->len)
			return 2 * inet_csk(sk)->icsk_ack.rcv_mss;

		truesize >>= 1;
		window >>= 1;
	}
	return 0;
}

/* Linux中实现了接收窗口的慢启动机制 */
static void tcp_grow_window(struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Check #1 */
	if (tp->rcv_ssthresh < tp->window_clamp &&
	    (int)tp->rcv_ssthresh < tcp_space(sk) &&
	    !sk_under_memory_pressure(sk)) {
		int incr;

		/* Check #2. Increase window, if skb with such overhead
		 * will fit to rcvbuf in future.
		 */
		if (tcp_win_from_space(skb->truesize) <= skb->len)
			incr = 2 * tp->advmss;
		else
			incr = __tcp_grow_window(sk, skb);

		if (incr) {
			incr = max_t(int, incr, 2 * skb->len);
			tp->rcv_ssthresh = min(tp->rcv_ssthresh + incr,
					       tp->window_clamp);
			inet_csk(sk)->icsk_ack.quick |= 1;
		}
	}
}

/* 3. Tuning rcvbuf, when connection enters established state. */

static void tcp_fixup_rcvbuf(struct sock *sk)
{
	u32 mss = tcp_sk(sk)->advmss;
	u32 icwnd = TCP_DEFAULT_INIT_RCVWND;
	int rcvmem;

	/* Limit to 10 segments if mss <= 1460,
	 * or 14600/mss segments, with a minimum of two segments.
	 */
	if (mss > 1460)
		icwnd = max_t(u32, (1460 * TCP_DEFAULT_INIT_RCVWND) / mss, 2);

	rcvmem = SKB_TRUESIZE(mss + MAX_TCP_HEADER);
	while (tcp_win_from_space(rcvmem) < mss)
		rcvmem += 128;

	rcvmem *= icwnd;

	if (sk->sk_rcvbuf < rcvmem)
		sk->sk_rcvbuf = min(rcvmem, sysctl_tcp_rmem[2]);
}

/* 4. Try to fixup all. It is made immediately after connection enters
 *    established state.
 */
void tcp_init_buffer_space(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int maxwin;

	if (!(sk->sk_userlocks & SOCK_RCVBUF_LOCK))
		tcp_fixup_rcvbuf(sk);
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK))
		tcp_fixup_sndbuf(sk);

	tp->rcvq_space.space = tp->rcv_wnd;

	maxwin = tcp_full_space(sk);

	if (tp->window_clamp >= maxwin) {
		tp->window_clamp = maxwin;

		if (sysctl_tcp_app_win && maxwin > 4 * tp->advmss)
			tp->window_clamp = max(maxwin -
					       (maxwin >> sysctl_tcp_app_win),
					       4 * tp->advmss);
	}

	/* Force reservation of one segment. */
	if (sysctl_tcp_app_win &&
	    tp->window_clamp > 2 * tp->advmss &&
	    tp->window_clamp + tp->advmss > maxwin)
		tp->window_clamp = max(2 * tp->advmss, maxwin - tp->advmss);

	tp->rcv_ssthresh = min(tp->rcv_ssthresh, tp->window_clamp);
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* 5. Recalculate window clamp after socket hit its memory bounds. */
/* 重新计算sk_rcvbuf和rcv_ssthresh, 主要的动机是：try to increase the quota for receive buffer */
static void tcp_clamp_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_ack.quick = 0;

    /* 如果tcp_rmem[2]还允许调大sk_rcvbuf，则进一步增大sk_rcvbuf */
	if (sk->sk_rcvbuf < sysctl_tcp_rmem[2] &&
	    !(sk->sk_userlocks & SOCK_RCVBUF_LOCK) &&
	    !sk_under_memory_pressure(sk) &&
	    sk_memory_allocated(sk) < sk_prot_mem_limits(sk, 0)) {
		sk->sk_rcvbuf = min(atomic_read(&sk->sk_rmem_alloc),
				    sysctl_tcp_rmem[2]);
	}
    /* 如果不能再调大sk_rcvbuf了，则只能强制的缩小rcv_ssthresh到2MSS */
	if (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf)
		tp->rcv_ssthresh = min(tp->window_clamp, 2U * tp->advmss);
}

/* Initialize RCV_MSS value.
 * RCV_MSS is an our guess about MSS used by the peer.
 * We haven't any direct information about the MSS.
 * It's better to underestimate the RCV_MSS rather than overestimate.
 * Overestimations make us ACKing less frequently than needed.
 * Underestimations are more easy to detect and fix by tcp_measure_rcv_mss().
 */
void tcp_initialize_rcv_mss(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned int hint = min_t(unsigned int, tp->advmss, tp->mss_cache);

	hint = min(hint, tp->rcv_wnd / 2);
	hint = min(hint, TCP_MSS_DEFAULT);
	hint = max(hint, TCP_MIN_MSS);

	inet_csk(sk)->icsk_ack.rcv_mss = hint;
}
EXPORT_SYMBOL(tcp_initialize_rcv_mss);

/* Receiver "autotuning" code.
 *
 * The algorithm for RTT estimation w/o timestamps is based on
 * Dynamic Right-Sizing (DRS) by Wu Feng and Mike Fisk of LANL.
 * <http://public.lanl.gov/radiant/pubs.html#DRS>
 *
 * More detail on this code can be found at
 * <http://staff.psc.edu/jheffner/>,
 * though this reference is out of date.  A new paper
 * is pending.
 */
static void tcp_rcv_rtt_update(struct tcp_sock *tp, u32 sample, int win_dep)
{
	u32 new_sample = tp->rcv_rtt_est.rtt;
	long m = sample;

	if (m == 0)
		m = 1;

	if (new_sample != 0) {
		/* If we sample in larger samples in the non-timestamp
		 * case, we could grossly overestimate the RTT especially
		 * with chatty applications or bulk transfer apps which
		 * are stalled on filesystem I/O.
		 *
		 * Also, since we are only going for a minimum in the
		 * non-timestamp case, we do not smooth things out
		 * else with timestamps disabled convergence takes too
		 * long.
		 */
		if (!win_dep) {
			m -= (new_sample >> 3);
			new_sample += m;
		} else {
			m <<= 3;
			if (m < new_sample)
				new_sample = m;
		}
	} else {
		/* No previous measure. */
		new_sample = m << 3;
	}

	if (tp->rcv_rtt_est.rtt != new_sample)
		tp->rcv_rtt_est.rtt = new_sample;
}

static inline void tcp_rcv_rtt_measure(struct tcp_sock *tp)
{
	if (tp->rcv_rtt_est.time == 0)
		goto new_measure;
	if (before(tp->rcv_nxt, tp->rcv_rtt_est.seq))
		return;
	tcp_rcv_rtt_update(tp, tcp_time_stamp - tp->rcv_rtt_est.time, 1);

new_measure:
	tp->rcv_rtt_est.seq = tp->rcv_nxt + tp->rcv_wnd;
	tp->rcv_rtt_est.time = tcp_time_stamp;
}

/* TODO: rcv rtt也有估计吗? */
static inline void tcp_rcv_rtt_measure_ts(struct sock *sk,
					  const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	if (tp->rx_opt.rcv_tsecr &&
	    (TCP_SKB_CB(skb)->end_seq -
	     TCP_SKB_CB(skb)->seq >= inet_csk(sk)->icsk_ack.rcv_mss))
		tcp_rcv_rtt_update(tp, tcp_time_stamp - tp->rx_opt.rcv_tsecr, 0);
}

/*
 * This function should be called every time data is copied to user space.
 * It calculates the appropriate TCP receive buffer space.
 */
/* TODO: */
void tcp_rcv_space_adjust(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int time;
	int space;

	if (tp->rcvq_space.time == 0)
		goto new_measure;

	time = tcp_time_stamp - tp->rcvq_space.time;
	if (time < (tp->rcv_rtt_est.rtt >> 3) || tp->rcv_rtt_est.rtt == 0)
		return;

	space = 2 * (tp->copied_seq - tp->rcvq_space.seq);

	space = max(tp->rcvq_space.space, space);

	if (tp->rcvq_space.space != space) {
		int rcvmem;

		tp->rcvq_space.space = space;

		if (sysctl_tcp_moderate_rcvbuf &&
		    !(sk->sk_userlocks & SOCK_RCVBUF_LOCK)) {
			int new_clamp = space;

			/* Receive space grows, normalize in order to
			 * take into account packet headers and sk_buff
			 * structure overhead.
			 */
			space /= tp->advmss;
			if (!space)
				space = 1;
			rcvmem = SKB_TRUESIZE(tp->advmss + MAX_TCP_HEADER);
			while (tcp_win_from_space(rcvmem) < tp->advmss)
				rcvmem += 128;
			space *= rcvmem;
			space = min(space, sysctl_tcp_rmem[2]);
			if (space > sk->sk_rcvbuf) {
				sk->sk_rcvbuf = space;

				/* Make the window clamp follow along.  */
				tp->window_clamp = new_clamp;
			}
		}
	}

new_measure:
	tp->rcvq_space.seq = tp->copied_seq;
	tp->rcvq_space.time = tcp_time_stamp;
}

/* There is something which you must keep in mind when you analyze the
 * behavior of the tp->ato delayed ack timeout interval.  When a
 * connection starts up, we want to ack as quickly as possible.  The
 * problem is that "good" TCP's do slow start at the beginning of data
 * transmission.  The means that until we send the first few ACK's the
 * sender will sit on his end and only queue most of his data, because
 * he can only send snd_cwnd unacked packets at any given time.  For
 * each ACK we send, he increments snd_cwnd and transmits more of his
 * queue.  -DaveM
 */
/* 收到按序到达的数据后，执行一下操作：
 *      a. 调度一个ACK。 TCP协议嘛，不回ACK就不乖了
 *      b. 测量receive mss
 *      c. 计算出一个新的receive window告知对端
 */
static void tcp_event_data_recv(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	u32 now;

    /* 收到一个数据包，理论上应该发送一个ACK。
     * 这里仅schedule，真正是否发送是有__tcp_ack_snd_check()来判断的
     */
	inet_csk_schedule_ack(sk);

	tcp_measure_rcv_mss(sk, skb);

	tcp_rcv_rtt_measure(tp);

	now = tcp_time_stamp;

	if (!icsk->icsk_ack.ato) {
		/* The _first_ data packet received, initialize
		 * delayed ACK engine.
		 */
		tcp_incr_quickack(sk);
		icsk->icsk_ack.ato = TCP_ATO_MIN;
	} else {
        /* 更新ATO值，分三种情况讨论 */
		int m = now - icsk->icsk_ack.lrcvtime;

		if (m <= TCP_ATO_MIN / 2) {
			/* The fastest case is the first. */
			icsk->icsk_ack.ato = (icsk->icsk_ack.ato >> 1) + TCP_ATO_MIN / 2;
		} else if (m < icsk->icsk_ack.ato) {
			icsk->icsk_ack.ato = (icsk->icsk_ack.ato >> 1) + m;
			if (icsk->icsk_ack.ato > icsk->icsk_rto)
				icsk->icsk_ack.ato = icsk->icsk_rto;
		} else if (m > icsk->icsk_rto) {
			/* Too long gap. Apparently sender failed to
			 * restart window, so that we send ACKs quickly.
			 */
			tcp_incr_quickack(sk);
			sk_mem_reclaim(sk);
		}
	}
	icsk->icsk_ack.lrcvtime = now;

	TCP_ECN_check_ce(tp, skb);

	if (skb->len >= 128)
		tcp_grow_window(sk, skb);
}

/* Called to compute a smoothed rtt estimate. The data fed to this
 * routine either comes from timestamps, or from segments that were
 * known _not_ to have been retransmitted [see Karn/Partridge
 * Proceedings SIGCOMM 87]. The algorithm is from the SIGCOMM 88
 * piece by Van Jacobson.
 * NOTE: the next three routines used to be one big routine.
 * To save cycles in the RFC 1323 implementation it was better to break
 * it up into three procedures. -- erics
 */
/* 理解下面的代码时，要记得一下几点：
 * 1. tp->srtt是8倍(<<3)的值，便于算法公式中的除以8
 * 2. tp->rttvar存的是4倍(<<2)的值,便于算法公式中的除以4
 */
static void tcp_rtt_estimator(struct sock *sk, const __u32 mrtt)
{
	struct tcp_sock *tp = tcp_sk(sk);
	long m = mrtt; /* RTT */

	/*	The following amusing code comes from Jacobson's
	 *	article in SIGCOMM '88.  Note that rtt and mdev
	 *	are scaled versions of rtt and mean deviation.
	 *	This is designed to be as fast as possible
	 *	m stands for "measurement".
	 *
	 *	On a 1990 paper the rto value is changed to:
	 *	RTO = rtt + 4 * mdev
	 *
	 * Funny. This algorithm seems to be very broken.
	 * These formulae increase RTO, when it should be decreased, increase
	 * too slowly, when it should be increased quickly, decrease too quickly
	 * etc. I guess in BSD RTO takes ONE value, so that it is absolutely
	 * does not matter how to _calculate_ it. Seems, it was trap
	 * that VJ failed to avoid. 8)
	 */
	if (m == 0)
		m = 1;
    /* srtt不为零说明已经收到过有效的rtt采样 */
	if (tp->srtt != 0) {
        /* 更新SRTT的理论公式： SRTT = (1 - alpha) * SRTT + alpha * RTT, 其中alpha=1/8 */
		m -= (tp->srtt >> 3);	/* m is now error in rtt est */     /* m <= RTT - SRTT */
        /* 代码实际上求的是： 8SRTT <= 7SRTT + RTT */
		tp->srtt += m;		/* rtt = 7/8 rtt + 1/8 new */   

		if (m < 0) {
			m = -m;		/* m is now abs(error) */ /* 取绝对值 */
			m -= (tp->mdev >> 2);   /* similar update on mdev */    /* m = |RTT - SRTT| - RTTVAR, 要记得tp->mdev存的是4倍的RTTVAR */
			/* This is similar to one of Eifel findings.
			 * Eifel blocks mdev updates when rtt decreases.
			 * This solution is a bit different: we use finer gain
			 * for mdev in this case (alpha*beta).
			 * Like Eifel it also prevents growth of rto,
			 * but also it limits too fast rto decreases,
			 * happening in pure Eifel.
			 */
            /* 此处m > 0，则表示此次的RTT采样与平滑的SRTT值差距较大，超过了RTTVAR
             * RTTVAR的理论计算公式为：RTTVAR = (1 - beta)RTTVAR + beta |RTT - SRTT|
             * 默认值beta = 1/4, 但实现时如果发现此次RTT采样较大，则选择beta=1/(4*8) */
			if (m > 0)
				m >>= 3;
		} else {
            /* m = |RTT - SRTT| - RTTVAR, 要记得tp->mdev存的是4倍的RTTVAR */
			m -= (tp->mdev >> 2);   /* similar update on mdev */
		}
        /* 代码实际求的是：4RTTVAR <= 3RTTVAR + |RTT - SRTT|, 等价于beta = 1/4
         * 如果上面发现RTT采样波动较大，则求的是 4RTTVAR <= (4 - 1/8)RTTVAR + 1/8 * |RTT - SRTT|, 等价于beta = 1/32 */
		tp->mdev += m;	    	/* mdev = 3/4 mdev + 1/4 new */

        /* 整整的RTTVAR会取最大的一个值, 以保证RTO只会计算的偏大，而不会偏小 */
		if (tp->mdev > tp->mdev_max) {
			tp->mdev_max = tp->mdev;
			if (tp->mdev_max > tp->rttvar)
				tp->rttvar = tp->mdev_max;
		}
        /* 如果经过了一个RTT，则适当降低RTTVAR，并重置mdev_max */
		if (after(tp->snd_una, tp->rtt_seq)) {
			if (tp->mdev_max < tp->rttvar)
                /* 适当的降低RTTVAR */
				tp->rttvar -= (tp->rttvar - tp->mdev_max) >> 2;
			tp->rtt_seq = tp->snd_nxt;      /* 用于记录新RTT周期的开始 */
			tp->mdev_max = tcp_rto_min(sk);
		}
	} else {
		/* no previous measure. */
        /* 第一次获得rtt采样时，令8SRTT = 8RTT，4RTTVAR = max( 2RTT, 200ms)
         * 而RTO = SRTT + 4RTTVAR, 保障RTO至少有3个RTT大小 */
		tp->srtt = m << 3;	/* take the measured time to be rtt */
		tp->mdev = m << 1;	/* make sure rto = 3*rtt */
		tp->mdev_max = tp->rttvar = max(tp->mdev, tcp_rto_min(sk));
		tp->rtt_seq = tp->snd_nxt;
	}
}

/* Calculate rto without backoff.  This is the second half of Van Jacobson's
 * routine referred to above.
 */
void tcp_set_rto(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	/* Old crap is replaced with new one. 8)
	 *
	 * More seriously:
	 * 1. If rtt variance happened to be less 50msec, it is hallucination.
	 *    It cannot be less due to utterly erratic ACK generation made
	 *    at least by solaris and freebsd. "Erratic ACKs" has _nothing_
	 *    to do with delayed acks, because at cwnd>2 true delack timeout
	 *    is invisible. Actually, Linux-2.4 also generates erratic
	 *    ACKs in some circumstances.
	 */
	inet_csk(sk)->icsk_rto = __tcp_set_rto(tp);

	/* 2. Fixups made earlier cannot be right.
	 *    If we do not estimate RTO correctly without them,
	 *    all the algo is pure shit and should be replaced
	 *    with correct one. It is exactly, which we pretend to do.
	 */

	/* NOTE: clamping at TCP_RTO_MIN is not required, current algo
	 * guarantees that rto is higher.
	 */
    /* 限制rto的最大值
     * 上面的注释中虽然说rto更新时不需要设置TCP_RTO_MIN，
     * 但这是因为更新srtt，rttvar的时候已经用过TCP_RTO_MIN进行限制了 */
	tcp_bound_rto(sk);
}

/* 返回初始拥塞窗口 */
__u32 tcp_init_cwnd(const struct tcp_sock *tp, const struct dst_entry *dst)
{
    /* 如果通过ip设置了某个固定route的初始拥塞窗口，那么使用这个值 */
	__u32 cwnd = (dst ? dst_metric(dst, RTAX_INITCWND) : 0);

    /* 否则使用默认的TCP_INIT_CWND值, 默认为10 */
	if (!cwnd)
		cwnd = TCP_INIT_CWND;
	return min_t(__u32, cwnd, tp->snd_cwnd_clamp);
}

/*
 * Packet counting of FACK is based on in-order assumptions, therefore TCP
 * disables it when reordering is detected
 */
void tcp_disable_fack(struct tcp_sock *tp)
{
	/* RFC3517 uses different metric in lost marker => reset on change */
	if (tcp_is_fack(tp))
		tp->lost_skb_hint = NULL;
	tp->rx_opt.sack_ok &= ~TCP_FACK_ENABLED;
}

/* Take a notice that peer is sending D-SACKs */
static void tcp_dsack_seen(struct tcp_sock *tp)
{
	tp->rx_opt.sack_ok |= TCP_DSACK_SEEN;
}

static void tcp_update_reordering(struct sock *sk, const int metric,
				  const int ts)
{
	struct tcp_sock *tp = tcp_sk(sk);
	if (metric > tp->reordering) {
		int mib_idx;

		tp->reordering = min(TCP_MAX_REORDERING, metric);

		/* This exciting event is worth to be remembered. 8) */
		if (ts)
			mib_idx = LINUX_MIB_TCPTSREORDER;
		else if (tcp_is_reno(tp))
			mib_idx = LINUX_MIB_TCPRENOREORDER;
		else if (tcp_is_fack(tp))
			mib_idx = LINUX_MIB_TCPFACKREORDER;
		else
			mib_idx = LINUX_MIB_TCPSACKREORDER;

		NET_INC_STATS_BH(sock_net(sk), mib_idx);
#if FASTRETRANS_DEBUG > 1
		pr_debug("Disorder%d %d %u f%u s%u rr%d\n",
			 tp->rx_opt.sack_ok, inet_csk(sk)->icsk_ca_state,
			 tp->reordering,
			 tp->fackets_out,
			 tp->sacked_out,
			 tp->undo_marker ? tp->undo_retrans : 0);
#endif
		tcp_disable_fack(tp);
	}

    /* 如果发现了更严重的reorder，就要选择关闭ER功能 */
	if (metric > 0)
		tcp_disable_early_retrans(tp);
}

/* This must be called before lost_out is incremented */
static void tcp_verify_retransmit_hint(struct tcp_sock *tp, struct sk_buff *skb)
{
    /* 如果没有设置过，或者当前要被标记为lost的skb的序号更小，则更新retransmit_skb_hint */
	if ((tp->retransmit_skb_hint == NULL) ||
	    before(TCP_SKB_CB(skb)->seq,
		   TCP_SKB_CB(tp->retransmit_skb_hint)->seq))
		tp->retransmit_skb_hint = skb;

    /* 如果lost_out为0，或者当前要被标记为lost的skb的尾序号更大，则更新retransmit_high */
	if (!tp->lost_out ||
	    after(TCP_SKB_CB(skb)->end_seq, tp->retransmit_high))
		tp->retransmit_high = TCP_SKB_CB(skb)->end_seq;
}

/* 将一个SKB标记为LOST */
static void tcp_skb_mark_lost(struct tcp_sock *tp, struct sk_buff *skb)
{
    /* 如果该SKB没有标记为lost, 也没有被SACK掉，则标记为lost */
	if (!(TCP_SKB_CB(skb)->sacked & (TCPCB_LOST|TCPCB_SACKED_ACKED))) {
		tcp_verify_retransmit_hint(tp, skb);

        /* 增加lost_out，标记TCPCB_LOST */
		tp->lost_out += tcp_skb_pcount(skb);
		TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
	}
}

/* 功能与tcp_skb_mark_lost()类似，就是在更新retrans hint的时候，不需要满足判断条件
 * TODO： 什么情况下会用该函数，而不用tcp_skb_mark_lost() ？ */
static void tcp_skb_mark_lost_uncond_verify(struct tcp_sock *tp,
					    struct sk_buff *skb)
{
	tcp_verify_retransmit_hint(tp, skb);

	if (!(TCP_SKB_CB(skb)->sacked & (TCPCB_LOST|TCPCB_SACKED_ACKED))) {
		tp->lost_out += tcp_skb_pcount(skb);
		TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
	}
}

/* This procedure tags the retransmission queue when SACKs arrive.
 *
 * We have three tag bits: SACKED(S), RETRANS(R) and LOST(L).
 * Packets in queue with these bits set are counted in variables
 * sacked_out, retrans_out and lost_out, correspondingly.
 *
 * Valid combinations are:
 * Tag  InFlight	Description
 * 0	1		- orig segment is in flight.
 * S	0		- nothing flies, orig reached receiver.
 * L	0		- nothing flies, orig lost by net.
 * R	2		- both orig and retransmit are in flight.
 * L|R	1		- orig is lost, retransmit is in flight.
 * S|R  1		- orig reached receiver, retrans is still in flight.
 * (L|S|R is logically valid, it could occur when L|R is sacked,
 *  but it is equivalent to plain S and code short-curcuits it to S.
 *  L|S is logically invalid, it would mean -1 packet in flight 8))
 *
 * These 6 states form finite state machine, controlled by the following events:
 * 1. New ACK (+SACK) arrives. (tcp_sacktag_write_queue())
 * 2. Retransmission. (tcp_retransmit_skb(), tcp_xmit_retransmit_queue())
 * 3. Loss detection event of two flavors:
 *	A. Scoreboard estimator decided the packet is lost.
 *	   A'. Reno "three dupacks" marks head of queue lost.
 *	   A''. Its FACK modification, head until snd.fack is lost.
 *	B. SACK arrives sacking SND.NXT at the moment, when the
 *	   segment was retransmitted.
 * 4. D-SACK added new rule: D-SACK changes any tag to S.
 *
 * It is pleasant to note, that state diagram turns out to be commutative,
 * so that we are allowed not to be bothered by order of our actions,
 * when multiple events arrive simultaneously. (see the function below).
 *
 * Reordering detection.
 * --------------------
 * Reordering metric is maximal distance, which a packet can be displaced
 * in packet stream. With SACKs we can estimate it:
 *
 * 1. SACK fills old hole and the corresponding segment was not
 *    ever retransmitted -> reordering. Alas, we cannot use it
 *    when segment was retransmitted.
 * 2. The last flaw is solved with D-SACK. D-SACK arrives
 *    for retransmitted and already SACKed segment -> reordering..
 * Both of these heuristics are not used in Loss state, when we cannot
 * account for retransmits accurately.
 *
 * SACK block validation.
 * ----------------------
 *
 * SACK block range validation checks that the received SACK block fits to
 * the expected sequence limits, i.e., it is between SND.UNA and SND.NXT.
 * Note that SND.UNA is not included to the range though being valid because
 * it means that the receiver is rather inconsistent with itself reporting
 * SACK reneging when it should advance SND.UNA. Such SACK block this is
 * perfectly valid, however, in light of RFC2018 which explicitly states
 * that "SACK block MUST reflect the newest segment.  Even if the newest
 * segment is going to be discarded ...", not that it looks very clever
 * in case of head skb. Due to potentional receiver driven attacks, we
 * choose to avoid immediate execution of a walk in write queue due to
 * reneging and defer head skb's loss recovery to standard loss recovery
 * procedure that will eventually trigger (nothing forbids us doing this).
 *
 * Implements also blockage to start_seq wrap-around. Problem lies in the
 * fact that though start_seq (s) is before end_seq (i.e., not reversed),
 * there's no guarantee that it will be before snd_nxt (n). The problem
 * happens when start_seq resides between end_seq wrap (e_w) and snd_nxt
 * wrap (s_w):
 *
 *         <- outs wnd ->                          <- wrapzone ->
 *         u     e      n                         u_w   e_w  s n_w
 *         |     |      |                          |     |   |  |
 * |<------------+------+----- TCP seqno space --------------+---------->|
 * ...-- <2^31 ->|                                           |<--------...
 * ...---- >2^31 ------>|                                    |<--------...
 *
 * Current code wouldn't be vulnerable but it's better still to discard such
 * crazy SACK blocks. Doing this check for start_seq alone closes somewhat
 * similar case (end_seq after snd_nxt wrap) as earlier reversed check in
 * snd_nxt wrap -> snd_una region will then become "well defined", i.e.,
 * equal to the ideal case (infinite seqno space without wrap caused issues).
 *
 * With D-SACK the lower bound is extended to cover sequence space below
 * SND.UNA down to undo_marker, which is the last point of interest. Yet
 * again, D-SACK block must not to go across snd_una (for the same reason as
 * for the normal SACK blocks, explained above). But there all simplicity
 * ends, TCP might receive valid D-SACKs below that. As long as they reside
 * fully below undo_marker they do not affect behavior in anyway and can
 * therefore be safely ignored. In rare cases (which are more or less
 * theoretical ones), the D-SACK will nicely cross that boundary due to skb
 * fragmentation and packet reordering past skb's retransmission. To consider
 * them correctly, the acceptable range must be extended even more though
 * the exact amount is rather hard to quantify. However, tp->max_window can
 * be used as an exaggerated estimate.
 */
/* 这个函数里面的判断都很好理解，但是真要无bug写出这些判断及顺序也非常不简单 */
static bool tcp_is_sackblock_valid(struct tcp_sock *tp, bool is_dsack,
				   u32 start_seq, u32 end_seq)
{
	/* Too far in future, or reversed (interpretation is ambiguous) */
	if (after(end_seq, tp->snd_nxt) || !before(start_seq, end_seq))
		return false;

	/* Nasty start_seq wrap-around check (see comments above) */
    /* 如果起始序号 > snd_nxt，则判定为无效
     * 尽管seq-wrap可能导致这种情况，目前的kernel选在宁可错杀(不要这个SACK信息)的保守方法*/
	if (!before(start_seq, tp->snd_nxt))
		return false;

	/* In outstanding window? ...This is valid exit for D-SACKs too.
	 * start_seq == snd_una is non-sensical (see comments above)
	 */
	if (after(start_seq, tp->snd_una))
		return true;

	if (!is_dsack || !tp->undo_marker)
		return false;

	/* ...Then it's D-SACK, and must reside below snd_una completely */
	if (after(end_seq, tp->snd_una))
		return false;

	if (!before(start_seq, tp->undo_marker))
		return true;

	/* Too old */
	if (!after(end_seq, tp->undo_marker))
		return false;

	/* Undo_marker boundary crossing (overestimates a lot). Known already:
	 *   start_seq < undo_marker and end_seq >= undo_marker.
	 */
	return !before(start_seq, end_seq - tp->max_window);
}

/* Check for lost retransmit. This superb idea is borrowed from "ratehalving".
 * Event "B". Later note: FACK people cheated me again 8), we have to account
 * for reordering! Ugly, but should help.
 *
 * Search retransmitted skbs from write_queue that were sent when snd_nxt was
 * less than what is now known to be received by the other end (derived from
 * highest SACK block). Also calculate the lowest snd_nxt among the remaining
 * retransmitted skbs to avoid some costly processing per ACKs.
 */
/* 标记已经被丢失的重传包 */
static void tcp_mark_lost_retrans(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int cnt = 0;
	u32 new_low_seq = tp->snd_nxt;
    /* received_upto 表示当前对端收到的序号值最大的值 */
	u32 received_upto = tcp_highest_sack_seq(tp);

	if (!tcp_is_fack(tp) || !tp->retrans_out ||
	    !after(received_upto, tp->lost_retrans_low) ||
	    icsk->icsk_ca_state != TCP_CA_Recovery)
		return;

	tcp_for_write_queue(skb, sk) {
        /* ack_seq变量存储的是重传该skb时的snd_nxt值 */
		u32 ack_seq = TCP_SKB_CB(skb)->ack_seq;

		if (skb == tcp_send_head(sk))
			break;
		if (cnt == tp->retrans_out)
			break;
		if (!after(TCP_SKB_CB(skb)->end_seq, tp->snd_una))
			continue;

		if (!(TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS))
			continue;

		/* TODO: We would like to get rid of tcp_is_fack(tp) only
		 * constraint here (see above) but figuring out that at
		 * least tp->reordering SACK blocks reside between ack_seq
		 * and received_upto is not easy task to do cheaply with
		 * the available datastructures.
		 *
		 * Whether FACK should check here for tp->reordering segs
		 * in-between one could argue for either way (it would be
		 * rather simple to implement as we could count fack_count
		 * during the walk and do tp->fackets_out - fack_count).
		 */
        /* 如果对端收到的序号最大的值，已经超过了skb重传时的snx_nxt，
         * 意味着某个在该重传包之后发送的新数据包已经被选择确认了，
         * 由此推断该重传包已经丢失
         */
		if (after(received_upto, ack_seq)) {
			TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_RETRANS;
			tp->retrans_out -= tcp_skb_pcount(skb);

			tcp_skb_mark_lost_uncond_verify(tp, skb);
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPLOSTRETRANSMIT);
		} else {
			if (before(ack_seq, new_low_seq))
				new_low_seq = ack_seq;
			cnt += tcp_skb_pcount(skb);
		}
	}

	if (tp->retrans_out)
		tp->lost_retrans_low = new_low_seq;
}

static bool tcp_check_dsack(struct sock *sk, const struct sk_buff *ack_skb,
			    struct tcp_sack_block_wire *sp, int num_sacks,
			    u32 prior_snd_una)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 start_seq_0 = get_unaligned_be32(&sp[0].start_seq);
	u32 end_seq_0 = get_unaligned_be32(&sp[0].end_seq);
	bool dup_sack = false;

	if (before(start_seq_0, TCP_SKB_CB(ack_skb)->ack_seq)) {
		dup_sack = true;
		tcp_dsack_seen(tp);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPDSACKRECV);
	} else if (num_sacks > 1) {
		u32 end_seq_1 = get_unaligned_be32(&sp[1].end_seq);
		u32 start_seq_1 = get_unaligned_be32(&sp[1].start_seq);

		if (!after(end_seq_0, end_seq_1) &&
		    !before(start_seq_0, start_seq_1)) {
			dup_sack = true;
			tcp_dsack_seen(tp);
			NET_INC_STATS_BH(sock_net(sk),
					LINUX_MIB_TCPDSACKOFORECV);
		}
	}

	/* D-SACK for already forgotten data... Do dumb counting. */
	if (dup_sack && tp->undo_marker && tp->undo_retrans &&
	    !after(end_seq_0, prior_snd_una) &&
	    after(end_seq_0, tp->undo_marker))
		tp->undo_retrans--;

	return dup_sack;
}

struct tcp_sacktag_state {
	int reord;
	int fack_count;
	int flag;
};

/* Check if skb is fully within the SACK block. In presence of GSO skbs,
 * the incoming SACK may not exactly match but we can find smaller MSS
 * aligned portion of it that matches. Therefore we might need to fragment
 * which may fail and creates some hassle (caller must handle error case
 * returns).
 *
 * FIXME: this could be merged to shift decision code
 */
static int tcp_match_skb_to_sack(struct sock *sk, struct sk_buff *skb,
				  u32 start_seq, u32 end_seq)
{
	int err;
	bool in_sack;
	unsigned int pkt_len;
	unsigned int mss;

	in_sack = !after(start_seq, TCP_SKB_CB(skb)->seq) &&
		  !before(end_seq, TCP_SKB_CB(skb)->end_seq);

	if (tcp_skb_pcount(skb) > 1 && !in_sack &&
	    after(TCP_SKB_CB(skb)->end_seq, start_seq)) {
		mss = tcp_skb_mss(skb);
		in_sack = !after(start_seq, TCP_SKB_CB(skb)->seq);

		if (!in_sack) {
			pkt_len = start_seq - TCP_SKB_CB(skb)->seq;
			if (pkt_len < mss)
				pkt_len = mss;
		} else {
			pkt_len = end_seq - TCP_SKB_CB(skb)->seq;
			if (pkt_len < mss)
				return -EINVAL;
		}

		/* Round if necessary so that SACKs cover only full MSSes
		 * and/or the remaining small portion (if present)
		 */
		if (pkt_len > mss) {
			unsigned int new_len = (pkt_len / mss) * mss;
			if (!in_sack && new_len < pkt_len) {
				new_len += mss;
				if (new_len > skb->len)
					return 0;
			}
			pkt_len = new_len;
		}
		err = tcp_fragment(sk, skb, pkt_len, mss);
		if (err < 0)
			return err;
	}

	return in_sack;
}

/* Mark the given newly-SACKed range as such, adjusting counters and hints. */
/* 给重传队列中的SKB打上SACK标记 */
static u8 tcp_sacktag_one(struct sock *sk,
			  struct tcp_sacktag_state *state, u8 sacked,
			  u32 start_seq, u32 end_seq,
			  bool dup_sack, int pcount)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int fack_count = state->fack_count;

	/* Account D-SACK for retransmitted packet. */
	if (dup_sack && (sacked & TCPCB_RETRANS)) {
		if (tp->undo_marker && tp->undo_retrans &&
		    after(end_seq, tp->undo_marker))
			tp->undo_retrans--;
		if (sacked & TCPCB_SACKED_ACKED)
			state->reord = min(fack_count, state->reord);
	}

	/* Nothing to do; acked frame is about to be dropped (was ACKed). */
	if (!after(end_seq, tp->snd_una))
		return sacked;

	if (!(sacked & TCPCB_SACKED_ACKED)) {
		if (sacked & TCPCB_SACKED_RETRANS) {
			/* If the segment is not tagged as lost,
			 * we do not clear RETRANS, believing
			 * that retransmission is still in flight.
			 */
			if (sacked & TCPCB_LOST) {
				sacked &= ~(TCPCB_LOST|TCPCB_SACKED_RETRANS);
				tp->lost_out -= pcount;
				tp->retrans_out -= pcount;
			}
		} else {
			if (!(sacked & TCPCB_RETRANS)) {
				/* New sack for not retransmitted frame,
				 * which was in hole. It is reordering.
				 */
				if (before(start_seq,
					   tcp_highest_sack_seq(tp)))
					state->reord = min(fack_count,
							   state->reord);
				if (!after(end_seq, tp->high_seq))
					state->flag |= FLAG_ORIG_SACK_ACKED;
			}

			if (sacked & TCPCB_LOST) {
				sacked &= ~TCPCB_LOST;
				tp->lost_out -= pcount;
			}
		}

        /* 为一个新的SACK block打上标记，并更新sacked_out值 */
		sacked |= TCPCB_SACKED_ACKED;
		state->flag |= FLAG_DATA_SACKED;
		tp->sacked_out += pcount;

		fack_count += pcount;

		/* Lost marker hint past SACKed? Tweak RFC3517 cnt */
		if (!tcp_is_fack(tp) && (tp->lost_skb_hint != NULL) &&
		    before(start_seq, TCP_SKB_CB(tp->lost_skb_hint)->seq))
			tp->lost_cnt_hint += pcount;

		if (fack_count > tp->fackets_out)
			tp->fackets_out = fack_count;
	}

	/* D-SACK. We can detect redundant retransmission in S|R and plain R
	 * frames and clear it. undo_retrans is decreased above, L|R frames
	 * are accounted above as well.
	 */
	if (dup_sack && (sacked & TCPCB_SACKED_RETRANS)) {
		sacked &= ~TCPCB_SACKED_RETRANS;
		tp->retrans_out -= pcount;
	}

	return sacked;
}

/* Shift newly-SACKed bytes from this skb to the immediately previous
 * already-SACKed sk_buff. Mark the newly-SACKed bytes as such.
 */
static bool tcp_shifted_skb(struct sock *sk, struct sk_buff *skb,
			    struct tcp_sacktag_state *state,
			    unsigned int pcount, int shifted, int mss,
			    bool dup_sack)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *prev = tcp_write_queue_prev(sk, skb);
	u32 start_seq = TCP_SKB_CB(skb)->seq;	/* start of newly-SACKed */
	u32 end_seq = start_seq + shifted;	/* end of newly-SACKed */

	BUG_ON(!pcount);

	/* Adjust counters and hints for the newly sacked sequence
	 * range but discard the return value since prev is already
	 * marked. We must tag the range first because the seq
	 * advancement below implicitly advances
	 * tcp_highest_sack_seq() when skb is highest_sack.
	 */
	tcp_sacktag_one(sk, state, TCP_SKB_CB(skb)->sacked,
			start_seq, end_seq, dup_sack, pcount);

	if (skb == tp->lost_skb_hint)
		tp->lost_cnt_hint += pcount;

	TCP_SKB_CB(prev)->end_seq += shifted;
	TCP_SKB_CB(skb)->seq += shifted;

	skb_shinfo(prev)->gso_segs += pcount;
	BUG_ON(skb_shinfo(skb)->gso_segs < pcount);
	skb_shinfo(skb)->gso_segs -= pcount;

	/* When we're adding to gso_segs == 1, gso_size will be zero,
	 * in theory this shouldn't be necessary but as long as DSACK
	 * code can come after this skb later on it's better to keep
	 * setting gso_size to something.
	 */
	if (!skb_shinfo(prev)->gso_size) {
		skb_shinfo(prev)->gso_size = mss;
		skb_shinfo(prev)->gso_type = sk->sk_gso_type;
	}

	/* CHECKME: To clear or not to clear? Mimics normal skb currently */
	if (skb_shinfo(skb)->gso_segs <= 1) {
		skb_shinfo(skb)->gso_size = 0;
		skb_shinfo(skb)->gso_type = 0;
	}

	/* Difference in this won't matter, both ACKed by the same cumul. ACK */
	TCP_SKB_CB(prev)->sacked |= (TCP_SKB_CB(skb)->sacked & TCPCB_EVER_RETRANS);

	if (skb->len > 0) {
		BUG_ON(!tcp_skb_pcount(skb));
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_SACKSHIFTED);
		return false;
	}

	/* Whole SKB was eaten :-) */

	if (skb == tp->retransmit_skb_hint)
		tp->retransmit_skb_hint = prev;
	if (skb == tp->scoreboard_skb_hint)
		tp->scoreboard_skb_hint = prev;
	if (skb == tp->lost_skb_hint) {
		tp->lost_skb_hint = prev;
		tp->lost_cnt_hint -= tcp_skb_pcount(prev);
	}

	TCP_SKB_CB(skb)->tcp_flags |= TCP_SKB_CB(prev)->tcp_flags;
	if (skb == tcp_highest_sack(sk))
		tcp_advance_highest_sack(sk, skb);

	tcp_unlink_write_queue(skb, sk);
	sk_wmem_free_skb(sk, skb);

	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_SACKMERGED);

	return true;
}

/* I wish gso_size would have a bit more sane initialization than
 * something-or-zero which complicates things
 */
static int tcp_skb_seglen(const struct sk_buff *skb)
{
	return tcp_skb_pcount(skb) == 1 ? skb->len : tcp_skb_mss(skb);
}

/* Shifting pages past head area doesn't work */
static int skb_can_shift(const struct sk_buff *skb)
{
	return !skb_headlen(skb) && skb_is_nonlinear(skb);
}

/* Try collapsing SACK blocks spanning across multiple skbs to a single
 * skb.
 */
static struct sk_buff *tcp_shift_skb_data(struct sock *sk, struct sk_buff *skb,
					  struct tcp_sacktag_state *state,
					  u32 start_seq, u32 end_seq,
					  bool dup_sack)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *prev;
	int mss;
	int pcount = 0;
	int len;
	int in_sack;

	if (!sk_can_gso(sk))
		goto fallback;

	/* Normally R but no L won't result in plain S */
	if (!dup_sack &&
	    (TCP_SKB_CB(skb)->sacked & (TCPCB_LOST|TCPCB_SACKED_RETRANS)) == TCPCB_SACKED_RETRANS)
		goto fallback;
	if (!skb_can_shift(skb))
		goto fallback;
	/* This frame is about to be dropped (was ACKed). */
	if (!after(TCP_SKB_CB(skb)->end_seq, tp->snd_una))
		goto fallback;

	/* Can only happen with delayed DSACK + discard craziness */
	if (unlikely(skb == tcp_write_queue_head(sk)))
		goto fallback;
	prev = tcp_write_queue_prev(sk, skb);

	if ((TCP_SKB_CB(prev)->sacked & TCPCB_TAGBITS) != TCPCB_SACKED_ACKED)
		goto fallback;

	in_sack = !after(start_seq, TCP_SKB_CB(skb)->seq) &&
		  !before(end_seq, TCP_SKB_CB(skb)->end_seq);

	if (in_sack) {
		len = skb->len;
		pcount = tcp_skb_pcount(skb);
		mss = tcp_skb_seglen(skb);

		/* TODO: Fix DSACKs to not fragment already SACKed and we can
		 * drop this restriction as unnecessary
		 */
		if (mss != tcp_skb_seglen(prev))
			goto fallback;
	} else {
		if (!after(TCP_SKB_CB(skb)->end_seq, start_seq))
			goto noop;
		/* CHECKME: This is non-MSS split case only?, this will
		 * cause skipped skbs due to advancing loop btw, original
		 * has that feature too
		 */
		if (tcp_skb_pcount(skb) <= 1)
			goto noop;

		in_sack = !after(start_seq, TCP_SKB_CB(skb)->seq);
		if (!in_sack) {
			/* TODO: head merge to next could be attempted here
			 * if (!after(TCP_SKB_CB(skb)->end_seq, end_seq)),
			 * though it might not be worth of the additional hassle
			 *
			 * ...we can probably just fallback to what was done
			 * previously. We could try merging non-SACKed ones
			 * as well but it probably isn't going to buy off
			 * because later SACKs might again split them, and
			 * it would make skb timestamp tracking considerably
			 * harder problem.
			 */
			goto fallback;
		}

		len = end_seq - TCP_SKB_CB(skb)->seq;
		BUG_ON(len < 0);
		BUG_ON(len > skb->len);

		/* MSS boundaries should be honoured or else pcount will
		 * severely break even though it makes things bit trickier.
		 * Optimize common case to avoid most of the divides
		 */
		mss = tcp_skb_mss(skb);

		/* TODO: Fix DSACKs to not fragment already SACKed and we can
		 * drop this restriction as unnecessary
		 */
		if (mss != tcp_skb_seglen(prev))
			goto fallback;

		if (len == mss) {
			pcount = 1;
		} else if (len < mss) {
			goto noop;
		} else {
			pcount = len / mss;
			len = pcount * mss;
		}
	}

	/* tcp_sacktag_one() won't SACK-tag ranges below snd_una */
	if (!after(TCP_SKB_CB(skb)->seq + len, tp->snd_una))
		goto fallback;

	if (!skb_shift(prev, skb, len))
		goto fallback;
	if (!tcp_shifted_skb(sk, skb, state, pcount, len, mss, dup_sack))
		goto out;

	/* Hole filled allows collapsing with the next as well, this is very
	 * useful when hole on every nth skb pattern happens
	 */
	if (prev == tcp_write_queue_tail(sk))
		goto out;
	skb = tcp_write_queue_next(sk, prev);

	if (!skb_can_shift(skb) ||
	    (skb == tcp_send_head(sk)) ||
	    ((TCP_SKB_CB(skb)->sacked & TCPCB_TAGBITS) != TCPCB_SACKED_ACKED) ||
	    (mss != tcp_skb_seglen(skb)))
		goto out;

	len = skb->len;
	if (skb_shift(prev, skb, len)) {
		pcount += tcp_skb_pcount(skb);
		tcp_shifted_skb(sk, skb, state, tcp_skb_pcount(skb), len, mss, 0);
	}

out:
	state->fack_count += pcount;
	return prev;

noop:
	return skb;

fallback:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_SACKSHIFTFALLBACK);
	return NULL;
}

static struct sk_buff *tcp_sacktag_walk(struct sk_buff *skb, struct sock *sk,
					struct tcp_sack_block *next_dup,
					struct tcp_sacktag_state *state,
					u32 start_seq, u32 end_seq,
					bool dup_sack_in)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *tmp;

	tcp_for_write_queue_from(skb, sk) {
		int in_sack = 0;
		bool dup_sack = dup_sack_in;

		if (skb == tcp_send_head(sk))
			break;

		/* queue is in-order => we can short-circuit the walk early */
		if (!before(TCP_SKB_CB(skb)->seq, end_seq))
			break;

		if ((next_dup != NULL) &&
		    before(TCP_SKB_CB(skb)->seq, next_dup->end_seq)) {
			in_sack = tcp_match_skb_to_sack(sk, skb,
							next_dup->start_seq,
							next_dup->end_seq);
			if (in_sack > 0)
				dup_sack = true;
		}

		/* skb reference here is a bit tricky to get right, since
		 * shifting can eat and free both this skb and the next,
		 * so not even _safe variant of the loop is enough.
		 */
		if (in_sack <= 0) {
			tmp = tcp_shift_skb_data(sk, skb, state,
						 start_seq, end_seq, dup_sack);
			if (tmp != NULL) {
				if (tmp != skb) {
					skb = tmp;
					continue;
				}

				in_sack = 0;
			} else {
				in_sack = tcp_match_skb_to_sack(sk, skb,
								start_seq,
								end_seq);
			}
		}

		if (unlikely(in_sack < 0))
			break;

        /* 如果判断这个SKB在一个SACK block内，则打上标记 */
		if (in_sack) {
			TCP_SKB_CB(skb)->sacked =
				tcp_sacktag_one(sk,
						state,
						TCP_SKB_CB(skb)->sacked,
						TCP_SKB_CB(skb)->seq,
						TCP_SKB_CB(skb)->end_seq,
						dup_sack,
						tcp_skb_pcount(skb));

			if (!before(TCP_SKB_CB(skb)->seq,
				    tcp_highest_sack_seq(tp)))
				tcp_advance_highest_sack(sk, skb);
		}

		state->fack_count += tcp_skb_pcount(skb);
	}
	return skb;
}

/* Avoid all extra work that is being done by sacktag while walking in
 * a normal way
 */
static struct sk_buff *tcp_sacktag_skip(struct sk_buff *skb, struct sock *sk,
					struct tcp_sacktag_state *state,
					u32 skip_to_seq)
{
	tcp_for_write_queue_from(skb, sk) {
		if (skb == tcp_send_head(sk))
			break;

		if (after(TCP_SKB_CB(skb)->end_seq, skip_to_seq))
			break;

		state->fack_count += tcp_skb_pcount(skb);
	}
	return skb;
}

static struct sk_buff *tcp_maybe_skipping_dsack(struct sk_buff *skb,
						struct sock *sk,
						struct tcp_sack_block *next_dup,
						struct tcp_sacktag_state *state,
						u32 skip_to_seq)
{
	if (next_dup == NULL)
		return skb;

	if (before(next_dup->start_seq, skip_to_seq)) {
		skb = tcp_sacktag_skip(skb, sk, state, next_dup->start_seq);
		skb = tcp_sacktag_walk(skb, sk, NULL, state,
				       next_dup->start_seq, next_dup->end_seq,
				       1);
	}

	return skb;
}

static int tcp_sack_cache_ok(const struct tcp_sock *tp, const struct tcp_sack_block *cache)
{
	return cache < tp->recv_sack_cache + ARRAY_SIZE(tp->recv_sack_cache);
}

/* 该函数负责详细的解析ACK包中的SACK option */
static int
tcp_sacktag_write_queue(struct sock *sk, const struct sk_buff *ack_skb,
			u32 prior_snd_una)
{
	struct tcp_sock *tp = tcp_sk(sk);
    /* 这里利用到了sacked选项在被解析时设置的偏移量，找到包头的SACK option内容 */
	const unsigned char *ptr = (skb_transport_header(ack_skb) +
				    TCP_SKB_CB(ack_skb)->sacked);   
    /* tcp_sack_block_wire 和tcp_sack_block 结构体都是RFC中的一个SACK block
     * 区别在于：
     * wire 表示ACK包中的网络字节序内容，没有wire的表示本机字节序内容
     */
	struct tcp_sack_block_wire *sp_wire = (struct tcp_sack_block_wire *)(ptr+2);
	struct tcp_sack_block sp[TCP_NUM_SACKS];
	struct tcp_sack_block *cache;
	struct tcp_sacktag_state state;
	struct sk_buff *skb;
    /* 计算SACK block的个数*/
	int num_sacks = min(TCP_NUM_SACKS, (ptr[1] - TCPOLEN_SACK_BASE) >> 3);  
	int used_sacks;
	bool found_dup_sack = false;
	int i, j;
	int first_sack_index;

	state.flag = 0; /* 该变量为函数返回值，初始化为0 */
	state.reord = tp->packets_out;

    /* (一个窗口内)如果之前没收到SACK，则要重置facked_out和highest sack
     * TODO-DONE 理解highest_sack含义:  最大的已经被SACK的序号 */
	if (!tp->sacked_out) {
		if (WARN_ON(tp->fackets_out))
			tp->fackets_out = 0;
		tcp_highest_sack_reset(sk);
	}

	found_dup_sack = tcp_check_dsack(sk, ack_skb, sp_wire,
					 num_sacks, prior_snd_una);
	if (found_dup_sack)
		state.flag |= FLAG_DSACKING_ACK;

	/* Eliminate too old ACKs, but take into
	 * account more or less fresh ones, they can
	 * contain valid SACK info.
	 */
	if (before(TCP_SKB_CB(ack_skb)->ack_seq, prior_snd_una - tp->max_window))
		return 0;

	if (!tp->packets_out)
		goto out;

	used_sacks = 0;
	first_sack_index = 0;
    /* for循环的目的就是对ACK包中的SACK信息进行细致的判断，只保存有效的到sp数组中 */
	for (i = 0; i < num_sacks; i++) {
		bool dup_sack = !i && found_dup_sack;

        /* 将网络字节序转换为本机字节序 */
		sp[used_sacks].start_seq = get_unaligned_be32(&sp_wire[i].start_seq);
		sp[used_sacks].end_seq = get_unaligned_be32(&sp_wire[i].end_seq);

        /* 判断sack block是否有效，无效返回false */
		if (!tcp_is_sackblock_valid(tp, dup_sack,
					    sp[used_sacks].start_seq,
					    sp[used_sacks].end_seq)) {
			int mib_idx;

			if (dup_sack) {
				if (!tp->undo_marker)
					mib_idx = LINUX_MIB_TCPDSACKIGNOREDNOUNDO;
				else
					mib_idx = LINUX_MIB_TCPDSACKIGNOREDOLD;
			} else {
				/* Don't count olds caused by ACK reordering */
				if ((TCP_SKB_CB(ack_skb)->ack_seq != tp->snd_una) &&
				    !after(sp[used_sacks].end_seq, tp->snd_una))
					continue;
				mib_idx = LINUX_MIB_TCPSACKDISCARD;
			}

			NET_INC_STATS_BH(sock_net(sk), mib_idx);
			if (i == 0)
				first_sack_index = -1;
			continue;
		}

		/* Ignore very old stuff early */
		if (!after(sp[used_sacks].end_seq, prior_snd_una))
			continue;

		used_sacks++;
	}

	/* order SACK blocks to allow in order walk of the retrans queue */
    /* 对sack block进行冒泡排序。要记得最多就4个block，^_^ */
	for (i = used_sacks - 1; i > 0; i--) {
		for (j = 0; j < i; j++) {
			if (after(sp[j].start_seq, sp[j + 1].start_seq)) {
				swap(sp[j], sp[j + 1]);

				/* Track where the first SACK block goes to */
                /* 第一个SACK block相对比较特殊，所以要记录好 */
				if (j == first_sack_index)
					first_sack_index = j + 1;
			}
		}
	}

	skb = tcp_write_queue_head(sk);
	state.fack_count = 0;
	i = 0;

	if (!tp->sacked_out) {
		/* It's already past, so skip checking against it */
		cache = tp->recv_sack_cache + ARRAY_SIZE(tp->recv_sack_cache);
	} else {
		cache = tp->recv_sack_cache;
		/* Skip empty blocks in at head of the cache */
		while (tcp_sack_cache_ok(tp, cache) && !cache->start_seq &&
		       !cache->end_seq)
			cache++;
	}

	while (i < used_sacks) {
		u32 start_seq = sp[i].start_seq;
		u32 end_seq = sp[i].end_seq;
		bool dup_sack = (found_dup_sack && (i == first_sack_index));
		struct tcp_sack_block *next_dup = NULL;

		if (found_dup_sack && ((i + 1) == first_sack_index))
			next_dup = &sp[i + 1];

		/* Skip too early cached blocks */
		while (tcp_sack_cache_ok(tp, cache) &&
		       !before(start_seq, cache->end_seq))
			cache++;

		/* Can skip some work by looking recv_sack_cache? */
		if (tcp_sack_cache_ok(tp, cache) && !dup_sack &&
		    after(end_seq, cache->start_seq)) {

			/* Head todo? */
			if (before(start_seq, cache->start_seq)) {
				skb = tcp_sacktag_skip(skb, sk, &state,
						       start_seq);
				skb = tcp_sacktag_walk(skb, sk, next_dup,
						       &state,
						       start_seq,
						       cache->start_seq,
						       dup_sack);
			}

			/* Rest of the block already fully processed? */
			if (!after(end_seq, cache->end_seq))
				goto advance_sp;

			skb = tcp_maybe_skipping_dsack(skb, sk, next_dup,
						       &state,
						       cache->end_seq);

			/* ...tail remains todo... */
			if (tcp_highest_sack_seq(tp) == cache->end_seq) {
				/* ...but better entrypoint exists! */
				skb = tcp_highest_sack(sk);
				if (skb == NULL)
					break;
				state.fack_count = tp->fackets_out;
				cache++;
				goto walk;
			}

			skb = tcp_sacktag_skip(skb, sk, &state, cache->end_seq);
			/* Check overlap against next cached too (past this one already) */
			cache++;
			continue;
		}

		if (!before(start_seq, tcp_highest_sack_seq(tp))) {
			skb = tcp_highest_sack(sk);
			if (skb == NULL)
				break;
			state.fack_count = tp->fackets_out;
		}
		skb = tcp_sacktag_skip(skb, sk, &state, start_seq);

walk:
		skb = tcp_sacktag_walk(skb, sk, next_dup, &state,
				       start_seq, end_seq, dup_sack);

advance_sp:
		i++;
	}

	/* Clear the head of the cache sack blocks so we can skip it next time */
	for (i = 0; i < ARRAY_SIZE(tp->recv_sack_cache) - used_sacks; i++) {
		tp->recv_sack_cache[i].start_seq = 0;
		tp->recv_sack_cache[i].end_seq = 0;
	}
	for (j = 0; j < used_sacks; j++)
		tp->recv_sack_cache[i++] = sp[j];

	tcp_mark_lost_retrans(sk);

	tcp_verify_left_out(tp);

	if ((state.reord < tp->fackets_out) &&
	    ((inet_csk(sk)->icsk_ca_state != TCP_CA_Loss) || tp->undo_marker))
		tcp_update_reordering(sk, tp->fackets_out - state.reord, 0);

out:

#if FASTRETRANS_DEBUG > 0
	WARN_ON((int)tp->sacked_out < 0);
	WARN_ON((int)tp->lost_out < 0);
	WARN_ON((int)tp->retrans_out < 0);
	WARN_ON((int)tcp_packets_in_flight(tp) < 0);
#endif
	return state.flag;
}

/* Limits sacked_out so that sum with lost_out isn't ever larger than
 * packets_out. Returns false if sacked_out adjustement wasn't necessary.
 */
static bool tcp_limit_reno_sacked(struct tcp_sock *tp)
{
	u32 holes;

	holes = max(tp->lost_out, 1U);
	holes = min(holes, tp->packets_out);

	if ((tp->sacked_out + holes) > tp->packets_out) {
		tp->sacked_out = tp->packets_out - holes;
		return true;
	}
	return false;
}

/* If we receive more dupacks than we expected counting segments
 * in assumption of absent reordering, interpret this as reordering.
 * The only another reason could be bug in receiver TCP.
 */
/* 如果收到的dupack个数超过了理论的预期值，说明可能还存在reorder，故选择更新reorder值 */
static void tcp_check_reno_reordering(struct sock *sk, const int addend)
{
	struct tcp_sock *tp = tcp_sk(sk);
	if (tcp_limit_reno_sacked(tp))
		tcp_update_reordering(sk, tp->packets_out + addend, 0);
}

/* Emulate SACKs for SACKless connection: account for a new dupack. */
static void tcp_add_reno_sack(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	tp->sacked_out++;
	tcp_check_reno_reordering(sk, 0);
	tcp_verify_left_out(tp);
}

/* Account for ACK, ACKing some data in Reno Recovery phase. */

static void tcp_remove_reno_sacks(struct sock *sk, int acked)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (acked > 0) {
		/* One ACK acked hole. The rest eat duplicate ACKs. */
		if (acked - 1 >= tp->sacked_out)
			tp->sacked_out = 0;
		else
			tp->sacked_out -= acked - 1;
	}
	tcp_check_reno_reordering(sk, acked);
	tcp_verify_left_out(tp);
}

/* 重置dupack计数器 */
static inline void tcp_reset_reno_sack(struct tcp_sock *tp)
{
	tp->sacked_out = 0;
}

/* 清理重传相关的计数器
 * 比如既然超时了，就默认之前retrans_out的包也都被丢掉了，
 * 所以选择将retrans_out设置为0. */
static void tcp_clear_retrans_partial(struct tcp_sock *tp)
{
	tp->retrans_out = 0;
	tp->lost_out = 0;

	tp->undo_marker = 0;
	tp->undo_retrans = 0;
}

void tcp_clear_retrans(struct tcp_sock *tp)
{
	tcp_clear_retrans_partial(tp);

	tp->fackets_out = 0;
	tp->sacked_out = 0;
}

/* Enter Loss state. If "how" is not zero, forget all SACK information
 * and reset tags completely, otherwise preserve SACKs. If receiver
 * dropped its ofo queue, we will know this due to reneging detection.
 */
/* how的作用可参考上面的注释，目前为止只有在tcp_check_sack_reneging函数中进入loss状态会设置how为1 */
void tcp_enter_loss(struct sock *sk, int how)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	bool new_recovery = false;

	/* Reduce ssthresh if it has not yet been made inside this window. */
    /* 1. 如果是open或disorder状态，那么ssthresh还没有被设置过
     * 2. 如果high_seq不比snd_una大，那么说明也没有被设置好，  -- high_seq是一个拥塞阶段开始时记录的snd_nxt值
     *      It means that in whatever state we are, all the data from the window that got us into the state,
     *      prior to retransmission timer expiry, has been acknowledged.
     * 3. 虽然已经设置了Loss状态，但还没能成功重传数据。
     *      The condition may arise in case we are not able to retransmit anything because of local congestion */
	if (icsk->icsk_ca_state <= TCP_CA_Disorder ||
	    !after(tp->high_seq, tp->snd_una) ||
	    (icsk->icsk_ca_state == TCP_CA_Loss && !icsk->icsk_retransmits)) {

		new_recovery = true;    /* 开始一段新的RTO重传之旅 */

        /* 注意：prior_ssthrehs可能获取的是当前cwnd的0.75倍，而不是真实的prior_ssthrehs值 */
		tp->prior_ssthresh = tcp_current_ssthresh(sk);
        /* 按照拥塞控制算法，重设ssthresh */
		tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
        /* 目前只有westwood中会关心这个event */
		tcp_ca_event(sk, CA_EVENT_LOSS);
	}

    /* 将cwnd设置为1，代价惨重啊 */
	tp->snd_cwnd	   = 1;
	tp->snd_cwnd_cnt   = 0;
	tp->snd_cwnd_stamp = tcp_time_stamp;

    /* 清理重传相关的计数器，比如retrans_out，因为既然都rto超时了，那些重传的包也会认为已经被丢掉了 */
	tcp_clear_retrans_partial(tp);

    /* 如果不支持SACK选项，sacked_out表示的dupack个数，也要重置了 */
	if (tcp_is_reno(tp))
		tcp_reset_reno_sack(tp);

    /* TODO-DONE: undo_marker是个什么鬼?
     * 记录重传开始的地方 */
	tp->undo_marker = tp->snd_una;

    /* 如果选择将SACK信息都忽视掉，则还要清除sack相关计数器 */
	if (how) {
		tp->sacked_out = 0;
		tp->fackets_out = 0;
	}
    /* TODO-DONE: retrans_hints是什么鬼？ */
    /* 标记在重传队列中，将要被重传的第一个SKB */
    /* RTO超时后，这个标记会被清除 */
	tcp_clear_all_retrans_hints(tp);

    /* 进一次loss状态，都会遍历一次整个重传队列啊，代价惨重 ! */
	tcp_for_write_queue(skb, sk) {
		if (skb == tcp_send_head(sk))
			break;

        /* 如果重传队列里面已经有一个数据包重传过，但还是进入了Loss状态，
         * 说明这次进入Loss可能是先进入了Recovery阶段在进入的了， 
         * 实现者认为这种由Open -> Recovery -> Loss的流程非常严重，不应该undo了，故选择将undo_marker清除 */
        /* 更准确的解释：由于之前已经重传过，那么当收到ACK时没办法确实是对于之前重传的确认，还是这次RTO之后的重传，
         * 因此此时不能undo.
         * ADI 解释：
         *      The reason being that we will never know if the ACK for packets appears from the retransmission
         *      or the original transmission. In the case where we get an ACK for retransmitted segment that is
         *      misinterpreted as an ACK for original segment and we undo from the loss state, this will be misleading.
         */
		if (TCP_SKB_CB(skb)->sacked & TCPCB_RETRANS)
			tp->undo_marker = 0;

        /* 在这三个标记中(TCPCB_SACKED_ACKED、TCPCB_SACKED_RETRANS、TCPCB_LOST)
         * 仅保留TCPCB_SACKED_ACKED标记。
         * 意思就是：保留SACK信息，清除retrans、lost标记 */
        /* TODO： 为什么要清除retrans和lost标记
         * 1. 清除retrans是因为尽管这个包重传过，但还是进入了loss状态，所以自然假设这个重传包也被丢弃了，保留retrans标记已经没有意义了 */
		TCP_SKB_CB(skb)->sacked &= (~TCPCB_TAGBITS)|TCPCB_SACKED_ACKED;

		if (!(TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)     /* 该SKB没有SACK信息 */
            || how) {                                           /* 或者需要忽略SACK信息 */
			TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_ACKED;     /* 清除ACK标记 */
			TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;              /* 标记lost标记 */
			tp->lost_out += tcp_skb_pcount(skb);                /* 既然把之前被SACK的包认为也丢弃了，则更新计数器 */
            /* TODO-DONE： retransmit_high的内在含义是？
             * 记录被标记为TCPCB_LOST标记的最大的序号 */
			tp->retransmit_high = TCP_SKB_CB(skb)->end_seq;
		}
	}
    /* 验证left_out (= sacked_out + lost_out) 不超过packets_out (= snd_nxt - snd_una) */
	tcp_verify_left_out(tp);

    /* 更新reordering值
     * reordering值在非loss阶段，可能被调大(比如通过DSACK信息), 
     * 但一旦进入Loss状态，则不相信之前的信息了，重新设置回系统默认值 */
	tp->reordering = min_t(unsigned int, tp->reordering,
			       sysctl_tcp_reordering);
	tcp_set_ca_state(sk, TCP_CA_Loss);
	tp->high_seq = tp->snd_nxt;     /* 设置进入Loss阶段的snd_nxt值 */
    /* 下一个发送的数据包的TCP头部会设置CWR bit, 通知对端cwnd已经被减小了。 */
	TCP_ECN_queue_cwr(tp);

	/* F-RTO RFC5682 sec 3.1 step 1: retransmit SND.UNA if no previous
	 * loss recovery is underway except recurring timeout(s) on
	 * the same SND.UNA (sec 3.2). Disable F-RTO on path MTU probing
	 */
    /* 标记启用frto机制，逻辑看上面注释即可。
     * TODO： 但为什么在已经不是第一次RTO的时候，依然进行FRTO？目前认为它有问题 */
	tp->frto = sysctl_tcp_frto &&
		   (new_recovery || icsk->icsk_retransmits) &&
		   !inet_csk(sk)->icsk_mtup.probe_size;
}

/* If ACK arrived pointing to a remembered SACK, it means that our
 * remembered SACKs do not reflect real state of receiver i.e.
 * receiver _host_ is heavily congested (or buggy).
 *
 * Do processing similar to RTO timeout.
 */
static bool tcp_check_sack_reneging(struct sock *sk, int flag)
{
	if (flag & FLAG_SACK_RENEGING) {
		struct inet_connection_sock *icsk = inet_csk(sk);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPSACKRENEGING);

		tcp_enter_loss(sk, 1);
		icsk->icsk_retransmits++;
		tcp_retransmit_skb(sk, tcp_write_queue_head(sk));
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					  icsk->icsk_rto, TCP_RTO_MAX);
		return true;
	}
	return false;
}

static inline int tcp_fackets_out(const struct tcp_sock *tp)
{
	return tcp_is_reno(tp) ? tp->sacked_out + 1 : tp->fackets_out;
}

/* Heurestics to calculate number of duplicate ACKs. There's no dupACKs
 * counter when SACK is enabled (without SACK, sacked_out is used for
 * that purpose).
 *
 * Instead, with FACK TCP uses fackets_out that includes both SACKed
 * segments up to the highest received SACK block so far and holes in
 * between them.
 * 从这段英文注释可以看出： fackets_out包括[snd_una, highest sack] 区间所有的数据包，不管它是SACKed，还是一个hole
 *
 * With reordering, holes may still be in flight, so RFC3517 recovery
 * uses pure sacked_out (total number of SACKed segments) even though
 * it violates the RFC that uses duplicate ACKs, often these are equal
 * but when e.g. out-of-window ACKs or packet duplication occurs,
 * they differ. Since neither occurs due to loss, TCP should really
 * ignore them.
 */
/* 推测出有多少个dupack */
static inline int tcp_dupack_heuristics(const struct tcp_sock *tp)
{
    /* TODO-DONE: sacked_out为什么还要加1 ？
     * 答：是因为判断返回值与reorderig大小的时候用的是>, 而不是>=。感觉这个地方好肤浅。。。 */
	return tcp_is_fack(tp) ? tp->fackets_out : tp->sacked_out + 1;
}

/* 返回true，表示需要pause一会在进入Recovery. 返回false则意味着立即进入Recovery */
static bool tcp_pause_early_retransmit(struct sock *sk, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned long delay;

	/* Delay early retransmit and entering fast recovery for
	 * max(RTT/4, 2msec) unless ack has ECE mark, no RTT samples
	 * available, or RTO is scheduled to fire first.
	 */
	if (sysctl_tcp_early_retrans < 2 ||     /* kernel没开delay ER的功能 */
        sysctl_tcp_early_retrans > 3 ||     /* kernel没开ER功能(这个地方与do_early_retrans的判断有重复，感觉有点多余 */
	    (flag & FLAG_ECE) ||                /* ECN: Explict Congestion Notification ECE: ECN-Echo */
        !tp->srtt)                          /* 没有RTT采样，没办法确定delay多久 */
		return false;

	delay = max_t(unsigned long, (tp->srtt >> 5), msecs_to_jiffies(2));
    /* 如果RTO先超时，则立即进入Recovery */
	if (!time_after(inet_csk(sk)->icsk_timeout, (jiffies + delay)))
		return false;

    /* 至此，就可以选择puase min(RTT/4, 2ms)在进入Recovery阶段，故设置ER超时定时器 */
    /* ICSK_TIME_EARLY_RETRANS的超时处理函数是tcp_resume_early_retransmit() */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_EARLY_RETRANS, delay,
				  TCP_RTO_MAX);
	return true;
}

/* 判断SKB的发送时间是否已经超过了RTO timer的时间 */
static inline int tcp_skb_timedout(const struct sock *sk,
				   const struct sk_buff *skb)
{
	return tcp_time_stamp - TCP_SKB_CB(skb)->when > inet_csk(sk)->icsk_rto;
}

/* 判断head skb的发送时间是否超过了RTO timer的时间 */
static inline int tcp_head_timedout(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return tp->packets_out &&
	       tcp_skb_timedout(sk, tcp_write_queue_head(sk));
}

/* Linux NewReno/SACK/FACK/ECN state machine.
 * --------------------------------------
 *
 * "Open"	Normal state, no dubious events, fast path.
 * "Disorder"   In all the respects it is "Open",
 *		but requires a bit more attention. It is entered when
 *		we see some SACKs or dupacks. It is split of "Open"
 *		mainly to move some processing from fast path to slow one.
 * "CWR"	CWND was reduced due to some Congestion Notification event.
 *		It can be ECN, ICMP source quench, local device congestion.
 * "Recovery"	CWND was reduced, we are fast-retransmitting.
 * "Loss"	CWND was reduced due to RTO timeout or SACK reneging.
 *
 * tcp_fastretrans_alert() is entered:
 * - each incoming ACK, if state is not "Open"
 * - when arrived ACK is unusual, namely:
 *	* SACK
 *	* Duplicate ACK.
 *	* ECN ECE.
 *
 * Counting packets in flight is pretty simple.
 *
 *	in_flight = packets_out - left_out + retrans_out
 *
 *	packets_out is SND.NXT-SND.UNA counted in packets.
 *
 *	retrans_out is number of retransmitted segments.
 *
 *	left_out is number of segments left network, but not ACKed yet.
 *
 *		left_out = sacked_out + lost_out
 *
 *     sacked_out: Packets, which arrived to receiver out of order
 *		   and hence not ACKed. With SACKs this number is simply
 *		   amount of SACKed data. Even without SACKs
 *		   it is easy to give pretty reliable estimate of this number,
 *		   counting duplicate ACKs.
 *
 *       lost_out: Packets lost by network. TCP has no explicit
 *		   "loss notification" feedback from network (for now).
 *		   It means that this number can be only _guessed_.
 *		   Actually, it is the heuristics to predict lossage that
 *		   distinguishes different algorithms.
 *
 *	F.e. after RTO, when all the queue is considered as lost,
 *	lost_out = packets_out and in_flight = retrans_out.
 *
 *		Essentially, we have now two algorithms counting
 *		lost packets.
 *
 *		FACK: It is the simplest heuristics. As soon as we decided
 *		that something is lost, we decide that _all_ not SACKed
 *		packets until the most forward SACK are lost. I.e.
 *		lost_out = fackets_out - sacked_out and left_out = fackets_out.
 *		It is absolutely correct estimate, if network does not reorder
 *		packets. And it loses any connection to reality when reordering
 *		takes place. We use FACK by default until reordering
 *		is suspected on the path to this destination.
 *
 *		NewReno: when Recovery is entered, we assume that one segment
 *		is lost (classic Reno). While we are in Recovery and
 *		a partial ACK arrives, we assume that one more packet
 *		is lost (NewReno). This heuristics are the same in NewReno
 *		and SACK.
 *
 *  Imagine, that's all! Forget about all this shamanism about CWND inflation
 *  deflation etc. CWND is real congestion window, never inflated, changes
 *  only according to classic VJ rules.
 *
 * Really tricky (and requiring careful tuning) part of algorithm
 * is hidden in functions tcp_time_to_recover() and tcp_xmit_retransmit_queue().
 * The first determines the moment _when_ we should reduce CWND and,
 * hence, slow down forward transmission. In fact, it determines the moment
 * when we decide that hole is caused by loss, rather than by a reorder.
 *
 * tcp_xmit_retransmit_queue() decides, _what_ we should retransmit to fill
 * holes, caused by lost packets.
 *
 * And the most logically complicated part of algorithm is undo
 * heuristics. We detect false retransmits due to both too early
 * fast retransmit (reordering) and underestimated RTO, analyzing
 * timestamps and D-SACKs. When we detect that some segments were
 * retransmitted by mistake and CWND reduction was wrong, we undo
 * window reduction and abort recovery phase. This logic is hidden
 * inside several functions named tcp_try_undo_<something>.
 */

/* This function decides, when we should leave Disordered state
 * and enter Recovery phase, reducing congestion window.
 *
 * Main question: may we further continue forward transmission
 * with the same cwnd?
 */
/* 该函数决定是否从 open/reorder/cwr这三个状态之一转换为Recovery 状态 */
/* 返回true，表示应该进入recovery状态 */
static bool tcp_time_to_recover(struct sock *sk, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 packets_out;

	/* Trick#1: The loss is proven. */
	if (tp->lost_out)
		return true;

	/* Not-A-Trick#2 : Classic rule... */
    /* 如果dupack个数达到reordering上限，即dupack thresh，则进入recovery阶段 */
	if (tcp_dupack_heuristics(tp) > tp->reordering)
		return true;

	/* Trick#3 : when we use RFC2988 timer restart, fast
	 * retransmit can be triggered by timeout of queue head.
	 */
	if (tcp_is_fack(tp) && tcp_head_timedout(sk))
		return true;

	/* Trick#4: It is still not OK... But will it be useful to delay
	 * recovery more?
	 */
	packets_out = tp->packets_out;
	if (packets_out <= tp->reordering &&
	    tp->sacked_out >= max_t(__u32, packets_out/2, sysctl_tcp_reordering) &&
	    !tcp_may_send_now(sk)) {
		/* We have nothing to send. This connection is limited
		 * either by receiver window or by application.
		 */
		return true;
	}

	/* If a thin stream is detected, retransmit after first
	 * received dupack. Employ only if SACK is supported in order
	 * to avoid possible corner-case series of spurious retransmissions
	 * Use only if there are no unsent data.
	 */
	if ((tp->thin_dupack || sysctl_tcp_thin_dupack) &&
	    tcp_stream_is_thin(tp) && tcp_dupack_heuristics(tp) > 1 &&
	    tcp_is_sack(tp) && !tcp_send_head(sk))
		return true;

	/* Trick#6: TCP early retransmit, per RFC5827.  To avoid spurious
	 * retransmissions due to small network reorderings, we implement
	 * Mitigation A.3 in the RFC and delay the retransmission for a short
	 * interval if appropriate.
	 */
    /* tp->packet_out >= (tp->sacked_out + 1) 这个地方为什么用>= ?这是Googler提出的enhanced ER机制
     *      Propose to allow a delayed early retransmit in the case where
     *      there are three outstanding segments that have not been cumulatively
     *      acknowledged and one segment that has been fully SACKed
     */
	if (tp->do_early_retrans &&                         /* 内核参数的配置允许开启ER */
        !tp->retrans_out &&                             /* 当前有重传数据 */
        tp->sacked_out &&                               /* 当前收到了dupack，或SACK block */
	    (tp->packets_out >= (tp->sacked_out + 1) &&     /* dupack个数满足ER/enhanced ER条件 */
        tp->packets_out < 4) &&                         /* packets_out很小，即RFC中oseg < 4 */
	    !tcp_may_send_now(sk))                          /* 没有新数据可以发送 */
		return !tcp_pause_early_retransmit(sk, flag);   /* 判断是否等待一段时间(1/4 RTT)再出发ER */

	return false;
}

/* New heuristics: it is possible only after we switched to restart timer
 * each time when something is ACKed. Hence, we can detect timed out packets
 * during fast retransmit without falling to slow start.
 *
 * Usefulness of this as is very questionable, since we should know which of
 * the segments is the next to timeout which is relatively expensive to find
 * in general case unless we add some data structure just for that. The
 * current approach certainly won't find the right one too often and when it
 * finally does find _something_ it usually marks large part of the window
 * right away (because a retransmission with a larger timestamp blocks the
 * loop from advancing). -ij
 */
/* 将重传队列中，所有"已发送时间"超过RTO timer的数据包标记为lost */
/* "已发送时间"定义：(now - skb->when > rto)
 */
static void tcp_timeout_skbs(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

    /* 如果不支持fast, 或者head skb的已发送时间还没有超过RTO timer
     * 则直接返回 */
	if (!tcp_is_fack(tp) || !tcp_head_timedout(sk))
		return;

    /* scoreboard_skb_hint指向scoreboard中，根据tcp_skb_timeout()判断为lost的最后一个skb位置 */
	skb = tp->scoreboard_skb_hint;
    /* 如果没有设置过，则指向重传队列的队首 */
	if (tp->scoreboard_skb_hint == NULL)
		skb = tcp_write_queue_head(sk);

	tcp_for_write_queue_from(skb, sk) {
		if (skb == tcp_send_head(sk))
			break;
        /* 如果该skb已发送时间超过RTO timer，则可以停止标记了 */
		if (!tcp_skb_timedout(sk, skb))
			break;

        /* 如果该skb已发送时间超过RTO timer(now - skb->when > rto), 则将数据包标记为LOST ! */
		tcp_skb_mark_lost(tp, skb);
	}

	tp->scoreboard_skb_hint = skb;

    /* 确认sacked_out + lost_out <= packet_out */
	tcp_verify_left_out(tp);
}

/* Detect loss in event "A" above by marking head of queue up as lost.
 * For FACK or non-SACK(Reno) senders, the first "packets" number of segments
 * are considered lost. For RFC3517 SACK, a segment is considered lost if it
 * has at least tp->reordering SACKed seqments above it; "packets" refers to
 * the maximum SACKed segments to pass before reaching this limit.
 */
static void tcp_mark_head_lost(struct sock *sk, int packets, int mark_head)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int cnt, oldcnt;
	int err;
	unsigned int mss;
	/* Use SACK to deduce losses of new sequences sent during recovery */
    /* 默认开启SACK，所以loss_high最多能到snd_nxt */
	const u32 loss_high = tcp_is_sack(tp) ?  tp->snd_nxt : tp->high_seq;

	WARN_ON(packets > tp->packets_out);
    /* lost_skb_hint标记从哪个位置开始标记为lost */
	if (tp->lost_skb_hint) {
		skb = tp->lost_skb_hint;
        /* lost_cnt_hint记录已经被标记为lost的个数 */
		cnt = tp->lost_cnt_hint;
		/* Head already handled? */
		if (mark_head && skb != tcp_write_queue_head(sk))
			return;
	} else {
		skb = tcp_write_queue_head(sk);
		cnt = 0;
	}

	tcp_for_write_queue_from(skb, sk) {
		if (skb == tcp_send_head(sk))
			break;
		/* TODO: do this better */
		/* this is not the most efficient way to do this... */
        /* 确实应该找到更好的办法更新这两个hint，每进一次循环都更新也是醉了 */
		tp->lost_skb_hint = skb;
		tp->lost_cnt_hint = cnt;

        /* 最多能将[snd_una, loss_high]区间内的SKB标记为lost */
		if (after(TCP_SKB_CB(skb)->end_seq, loss_high))
			break;

		oldcnt = cnt;
        /* 更新cnt值，即标记为lost的个数 */
        /* 默认开启fack，所以cnt默认会递增；
         * 如果后续fack被disable了，SACK开启工作。 要记住packets参数的含义:
         *     the maximum SACKed segments to pass before reaching this limit
         * 即使用SACK时，packet表示一路标记，直到遍历超过packets个SACKed SKB时停止 */
		if (tcp_is_fack(tp) || tcp_is_reno(tp) ||
		    (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED))
			cnt += tcp_skb_pcount(skb);

		if (cnt > packets) {
            /* 如果仅使用了SACK机制，也直接break */
            /* 在不需要分片的情况下，oldcnt == packets肯定成立，从而break出去了 */
			if ((tcp_is_sack(tp) && !tcp_is_fack(tp)) ||
			    (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED) ||
			    (oldcnt >= packets))
				break;

            /* 处理边界情况：需要切片 */
			mss = skb_shinfo(skb)->gso_size;
			err = tcp_fragment(sk, skb, (packets - oldcnt) * mss, mss);
			if (err < 0)
				break;
			cnt = packets;
		}

		tcp_skb_mark_lost(tp, skb);

        /* 如果只需要将head标记为lost，则至此就可以break了 */
		if (mark_head)
			break;
	}
	tcp_verify_left_out(tp);
}

/* Account newly detected lost packet(s) */
/* 更新scoreboard */
static void tcp_update_scoreboard(struct sock *sk, int fast_rexmit)
{
	struct tcp_sock *tp = tcp_sk(sk);

    /* 如果不支持sack，则仅将head标记为lost */
	if (tcp_is_reno(tp)) {
		tcp_mark_head_lost(sk, 1, 1);
	} else if (tcp_is_fack(tp)) {
        /* 如果支持fack, 则将[snd_una, highest sacked seq]之间的所有未被(选择)确认的数据包认为已经丢弃
         * 当然，还需要容忍一定程度的reordering 
         * sysctl_tcp_fack选项已经默认开启 */
        /* reordering是当前已经检测数来的reordering数量，默认为3
         * fackest_out是[snd_una, highest sack]区间内所有的数据包的个数
         */
		int lost = tp->fackets_out - tp->reordering;
		if (lost <= 0)
			lost = 1;
        /* 使用fack时，不是直接mark head, 而是mark lost个数，所以第三个参数为0 */
		tcp_mark_head_lost(sk, lost, 0);
	} else {
        /* 如果支持sack */
        /* sacked_out表示被SACKED的skb的个数 */
        /* TODO-DONE: 这里会出现sacked_upto == 0的情况，这样即使设置了fast_rexmit，
         * 也还是会调用tcp_mark_head_lost(sk, 0, 0) 这样的结果是什么？
         * 答：使用SACK时，packets参数(即sacked_upto)表示的含义是标记lost时，最多能够遇到的SACKed SKB的个数
         * 所以如果sacked_upto的值为0，则表示将[snd_una, lowest sack seq]之间的所有块都标记为LOST!!! */
		int sacked_upto = tp->sacked_out - tp->reordering;
		if (sacked_upto >= 0)
			tcp_mark_head_lost(sk, sacked_upto, 0);
		else if (fast_rexmit)
            /* 如果标记为快速重传，则将head标记为lost */
			tcp_mark_head_lost(sk, 1, 1);
	}

    /* 将重传队列中，已发送时间超过RTO的skb也设置为LOST */
	tcp_timeout_skbs(sk);
}

/* CWND moderation, preventing bursts due to too big ACKs
 * in dubious situations.
 */
static inline void tcp_moderate_cwnd(struct tcp_sock *tp)
{
	tp->snd_cwnd = min(tp->snd_cwnd,
			   tcp_packets_in_flight(tp) + tcp_max_burst(tp));
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* Nothing was retransmitted or returned timestamp is less
 * than timestamp of the first retransmission.
 */
static inline bool tcp_packet_delayed(const struct tcp_sock *tp)
{
	return !tp->retrans_stamp ||    /* 如果之前未发送过重传数据包，则可以undo */
        /* 如果支持timestamp，并且也收到了tsecr，并且收到的这个数据包的timestamp
         * 比这次重传开始时间还早，那么也能证明重传是多余的，可以undo */
		(tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr &&
		 before(tp->rx_opt.rcv_tsecr, tp->retrans_stamp));
}

/* Undo procedures. */

#if FASTRETRANS_DEBUG > 1
static void DBGUNDO(struct sock *sk, const char *msg)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);

	if (sk->sk_family == AF_INET) {
		pr_debug("Undo %s %pI4/%u c%u l%u ss%u/%u p%u\n",
			 msg,
			 &inet->inet_daddr, ntohs(inet->inet_dport),
			 tp->snd_cwnd, tcp_left_out(tp),
			 tp->snd_ssthresh, tp->prior_ssthresh,
			 tp->packets_out);
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (sk->sk_family == AF_INET6) {
		struct ipv6_pinfo *np = inet6_sk(sk);
		pr_debug("Undo %s %pI6/%u c%u l%u ss%u/%u p%u\n",
			 msg,
			 &np->daddr, ntohs(inet->inet_dport),
			 tp->snd_cwnd, tcp_left_out(tp),
			 tp->snd_ssthresh, tp->prior_ssthresh,
			 tp->packets_out);
	}
#endif
}
#else
#define DBGUNDO(x...) do { } while (0)
#endif

/* 负责实际撤销cwnd reduction */
static void tcp_undo_cwr(struct sock *sk, const bool undo_ssthresh)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->prior_ssthresh) {
		const struct inet_connection_sock *icsk = inet_csk(sk);

        /* 如果拥塞拥塞算法有自身的undo_cwnd处理函数，则调用拥塞算法自身的处理函数 */
		if (icsk->icsk_ca_ops->undo_cwnd)
			tp->snd_cwnd = icsk->icsk_ca_ops->undo_cwnd(sk);
		else
        /* ssthresh一般就是reduce cwnd之前的cwnd值的一半，因此至少要将cwnd恢复成ssthresh的两倍 */
			tp->snd_cwnd = max(tp->snd_cwnd, tp->snd_ssthresh << 1);

        /* 如果同时需要恢复慢启动阈值，则将ssthresh恢复为prior_ssthresh */
		if (undo_ssthresh && tp->prior_ssthresh > tp->snd_ssthresh) {
			tp->snd_ssthresh = tp->prior_ssthresh;
			TCP_ECN_withdraw_cwr(tp);   /* TODO： 标记不再信任ECN提供的cwr信息 ？ */
		}
	} else {
        /* 如果没有保存过之前的ssthresh，则仅将cwnd恢复到当前ssthresh */
		tp->snd_cwnd = max(tp->snd_cwnd, tp->snd_ssthresh);
	}
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* 判断是否能撤销cwnd的调整
 * 由于TCP无法明确的知道某个包是真的丢了，还是被延迟了。尽管TCP使用许多技术(如SACK，FACK)等机制来推测丢包，但依然可能进行了误判。
 * 当TCP误判某个包丢失时，可能进入recovery或loss状态，不管具体进入哪一个，都会调整拥塞窗口，而且是调小。
 * 因此后续发现了足够的证据，发现是误判，那么TCP会尝试undo之前的reduction。
 *
 * 当满足以下条件之一时，则可以undo cwnd reduction了
 * 1. undo_retrans等于0
 *      最近一次恢复期间重传的数据包个数为undo_retrans
 *      如果收到了足够的D-SACK信息，将undo_retrans减到0了，则说明重传是没有必要的，进而可以undo
 * 2. 如果之前未发送过重传数据包，则可以undo    
 * 3. 如果支持timestamp，并且也收到了tsecr，并且收到的这个数据包的timestamp
 *    比这次重传开始时间还早，那么也能证明重传是多余的，可以undo
 * tcp_packet_delayed(tp)判断条件2和3. */
static inline bool tcp_may_undo(const struct tcp_sock *tp)
{
    /* 首先必须设置了undo_marker才能undo, undo_marker表示重传开始的位置, 如果没有被设置，想undo也不知道往哪undo
     *      -- 注意在tcp_enter_loss时，如果发现有数据包已经重传过，但还是进入了loss，则会强制清零undo_marker，表示这种情况下不给undo的机会 
     */
	return tp->undo_marker && (!tp->undo_retrans || tcp_packet_delayed(tp));
}

/* People celebrate: "We love our President!" */
static bool tcp_try_undo_recovery(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tcp_may_undo(tp)) {
        /* 如果可以进行undo */
		int mib_idx;

		/* Happy end! We did not retransmit anything
		 * or our original transmission succeeded.
		 */
		DBGUNDO(sk, inet_csk(sk)->icsk_ca_state == TCP_CA_Loss ? "loss" : "retrans");
		tcp_undo_cwr(sk, true);     /* 撤销cwnd reduction */
		if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss)
			mib_idx = LINUX_MIB_TCPLOSSUNDO;
		else
			mib_idx = LINUX_MIB_TCPFULLUNDO;

		NET_INC_STATS_BH(sock_net(sk), mib_idx);
		tp->undo_marker = 0;
	}
    /* 如果不支持SACK，并且high_seq(在开始准备降低cwnd时记录的snd_nxt)已经被按序确认了，
     * 那么有可能这个ack确认了大量的数据，要防止burst */
	if (tp->snd_una == tp->high_seq && tcp_is_reno(tp)) {
		/* Hold old state until something *above* high_seq
		 * is ACKed. For Reno it is MUST to prevent false
		 * fast retransmits (RFC2582). SACK TCP is safe. */
		tcp_moderate_cwnd(tp);
		return true;
	}
	tcp_set_ca_state(sk, TCP_CA_Open);
	return false;
}

/* Try to undo cwnd reduction, because D-SACKs acked all retransmitted data */
static void tcp_try_undo_dsack(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

    /* D-SACK可以通知发送方，新到的段已经接收过的。
     * 如果所有在最近一次恢复期间重传的数据段都被D-SACK确认了，则发送方知道这此重传是不必要触发的 */
	if (tp->undo_marker && !tp->undo_retrans) {
		DBGUNDO(sk, "D-SACK");
		tcp_undo_cwr(sk, true); /* 恢复cwnd，并且也恢复ssthresh */
		tp->undo_marker = 0;    /* undo_marker标记的是重传开始的位置，undo一次后自然要归零 */
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPDSACKUNDO); /* 记录通过DSACK信息undocwnd reduction的次数 */
	}
}

/* We can clear retrans_stamp when there are no retransmissions in the
 * window. It would seem that it is trivially available for us in
 * tp->retrans_out, however, that kind of assumptions doesn't consider
 * what will happen if errors occur when sending retransmission for the
 * second time. ...It could the that such segment has only
 * TCPCB_EVER_RETRANS set at the present time. It seems that checking
 * the head skb is enough except for some reneging corner cases that
 * are not worth the effort.
 *
 * Main reason for all this complexity is the fact that connection dying
 * time now depends on the validity of the retrans_stamp, in particular,
 * that successive retransmissions of a segment must not advance
 * retrans_stamp under any conditions.
 */
/* 严谨的判断是否有数据重传过, 如果有则返回true, 否则返回false */
static bool tcp_any_retrans_done(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

    /* 如果明确的有retrans_out数据，则证明当前网络中有未确认的重传包 */
	if (tp->retrans_out)
		return true;

	skb = tcp_write_queue_head(sk);
    /* 发送队列中的第一个数据包曾经发生过重传 */
	if (unlikely(skb && TCP_SKB_CB(skb)->sacked & TCPCB_EVER_RETRANS))
		return true;

	return false;
}

/* Undo during fast recovery after partial ACK. */
/* TODO: 这个partial ACK为什么能判断出要undo ? */
static int tcp_try_undo_partial(struct sock *sk, int acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	/* Partial ACK arrived. Force Hoe's retransmit. */
    /* 如果不支持SACK，或者乱序已经超过reordering，则理论上应该返回failed，启动Hoe's retransmit */
    /* TODO: Hoe's retransmit到底是什么 */
	int failed = tcp_is_reno(tp) || (tcp_fackets_out(tp) > tp->reordering);

	if (tcp_may_undo(tp)) {
		/* Plain luck! Hole if filled with delayed
		 * packet, rather than with a retransmit.
		 */
        /* 如果没有数据重传过，则将retrans_stamp清零 */
		if (!tcp_any_retrans_done(sk))
			tp->retrans_stamp = 0;

		tcp_update_reordering(sk, tcp_fackets_out(tp) + acked, 1);

		DBGUNDO(sk, "Hoe");
		tcp_undo_cwr(sk, false);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPPARTIALUNDO);

		/* So... Do not make Hoe's retransmit yet.
		 * If the first packet was delayed, the rest
		 * ones are most probably delayed as well.
		 */
		failed = 0;
	}
	return failed;
}

/* Undo during loss recovery after partial ACK or using F-RTO. */
static bool tcp_try_undo_loss(struct sock *sk, bool frto_undo)
{
	struct tcp_sock *tp = tcp_sk(sk);

    /* 如果通过F-RTO发现要undo，或者其他机制(D-SACK，timestamp)发现要undo */
	if (frto_undo || tcp_may_undo(tp)) {
		struct sk_buff *skb;
        /* 取消scoreboard中的所有loss标记 */
		tcp_for_write_queue(skb, sk) {
			if (skb == tcp_send_head(sk))
				break;
			TCP_SKB_CB(skb)->sacked &= ~TCPCB_LOST;
		}

		tcp_clear_all_retrans_hints(tp);

		DBGUNDO(sk, "partial loss");
		tp->lost_out = 0;
		tcp_undo_cwr(sk, true);     /* 撤销cwnd reduction */
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPLOSSUNDO);
		if (frto_undo)
			NET_INC_STATS_BH(sock_net(sk),
					 LINUX_MIB_TCPSPURIOUSRTOS);
		inet_csk(sk)->icsk_retransmits = 0;
		tp->undo_marker = 0;
        /* 如果是F-RTO发现要undo, 或者是支持SACK，则将状态恢复为Open */
        /* TODO: 为什么不支持SACK不行？ */
		if (frto_undo || tcp_is_sack(tp))
			tcp_set_ca_state(sk, TCP_CA_Open);
		return true;
	}
	return false;
}

/* The cwnd reduction in CWR and Recovery use the PRR algorithm
 * https://datatracker.ietf.org/doc/draft-ietf-tcpm-proportional-rate-reduction/
 * It computes the number of packets to send (sndcnt) based on packets newly
 * delivered:
 *   1) If the packets in flight is larger than ssthresh, PRR spreads the
 *	cwnd reductions across a full RTT.
 *   2) If packets in flight is lower than ssthresh (such as due to excess
 *	losses and/or application stalls), do not perform any further cwnd
 *	reductions, but instead slow start up to ssthresh.
 */
static void tcp_init_cwnd_reduction(struct sock *sk, const bool set_ssthresh)
{
	struct tcp_sock *tp = tcp_sk(sk);

    /* 发现拥塞了，high_seq记录此时的snd_nxt
     * 只有后续snd_una超过这个值才会退出cwnd reduction */
	tp->high_seq = tp->snd_nxt;     

	tp->tlp_high_seq = 0;
	tp->snd_cwnd_cnt = 0;
	tp->prior_cwnd = tp->snd_cwnd;
	tp->prr_delivered = 0;
	tp->prr_out = 0;
	if (set_ssthresh)
		tp->snd_ssthresh = inet_csk(sk)->icsk_ca_ops->ssthresh(sk);
	TCP_ECN_queue_cwr(tp);
}

static void tcp_cwnd_reduction(struct sock *sk, int newly_acked_sacked,
			       int fast_rexmit)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int sndcnt = 0;
	int delta = tp->snd_ssthresh - tcp_packets_in_flight(tp);

	tp->prr_delivered += newly_acked_sacked;
	if (tcp_packets_in_flight(tp) > tp->snd_ssthresh) {
		u64 dividend = (u64)tp->snd_ssthresh * tp->prr_delivered +
			       tp->prior_cwnd - 1;
		sndcnt = div_u64(dividend, tp->prior_cwnd) - tp->prr_out;
	} else {
		sndcnt = min_t(int, delta,
			       max_t(int, tp->prr_delivered - tp->prr_out,
				     newly_acked_sacked) + 1);
	}

	sndcnt = max(sndcnt, (fast_rexmit ? 1 : 0));
	tp->snd_cwnd = tcp_packets_in_flight(tp) + sndcnt;
}

static inline void tcp_end_cwnd_reduction(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Reset cwnd to ssthresh in CWR or Recovery (unless it's undone) */
	if (inet_csk(sk)->icsk_ca_state == TCP_CA_CWR ||
	    (tp->undo_marker && tp->snd_ssthresh < TCP_INFINITE_SSTHRESH)) {
		tp->snd_cwnd = tp->snd_ssthresh;
		tp->snd_cwnd_stamp = tcp_time_stamp;
	}
	tcp_ca_event(sk, CA_EVENT_COMPLETE_CWR);
}

/* Enter CWR state. Disable cwnd undo since congestion is proven with ECN */
/* 进入CWR状态 */
void tcp_enter_cwr(struct sock *sk, const int set_ssthresh)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->prior_ssthresh = 0;
    /* 只有Open和Disorder状态才能进入 */
	if (inet_csk(sk)->icsk_ca_state < TCP_CA_CWR) {
		tp->undo_marker = 0;    /* 清除重传开始的位置记录 */
        /* 要开始降低cwnd了，初始化一些相关参数
         * 从目前的实现来看，进入CWR状态的set_ssthresh恒为1，即要重设慢启动阈值 */
		tcp_init_cwnd_reduction(sk, set_ssthresh);
		tcp_set_ca_state(sk, TCP_CA_CWR);
	}
}

static void tcp_try_keep_open(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int state = TCP_CA_Open;

    /* 如果有被SACK的数据包，或有被推断为loss的数据包，或者已经发送过重传包 */
	if (tcp_left_out(tp) || tcp_any_retrans_done(sk))
		state = TCP_CA_Disorder;

    /* 如果以上情况都没有，则转换到TCP_CA_Open状态 */
	if (inet_csk(sk)->icsk_ca_state != state) {
		tcp_set_ca_state(sk, state);
		tp->high_seq = tp->snd_nxt;     /* 设置开始进入Open，或Disorder状态时的snd_nxt */
	}
}

static void tcp_try_to_open(struct sock *sk, int flag, int newly_acked_sacked)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_verify_left_out(tp);

	if (!tcp_any_retrans_done(sk))
		tp->retrans_stamp = 0;

	if (flag & FLAG_ECE)
		tcp_enter_cwr(sk, 1);

	if (inet_csk(sk)->icsk_ca_state != TCP_CA_CWR) {
		tcp_try_keep_open(sk);
		if (inet_csk(sk)->icsk_ca_state != TCP_CA_Open)
			tcp_moderate_cwnd(tp);
	} else {
		tcp_cwnd_reduction(sk, newly_acked_sacked, 0);
	}
}

static void tcp_mtup_probe_failed(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_mtup.search_high = icsk->icsk_mtup.probe_size - 1;
	icsk->icsk_mtup.probe_size = 0;
}

static void tcp_mtup_probe_success(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	/* FIXME: breaks with very large cwnd */
	tp->prior_ssthresh = tcp_current_ssthresh(sk);
	tp->snd_cwnd = tp->snd_cwnd *
		       tcp_mss_to_mtu(sk, tp->mss_cache) /
		       icsk->icsk_mtup.probe_size;
	tp->snd_cwnd_cnt = 0;
	tp->snd_cwnd_stamp = tcp_time_stamp;
	tp->snd_ssthresh = tcp_current_ssthresh(sk);

	icsk->icsk_mtup.search_low = icsk->icsk_mtup.probe_size;
	icsk->icsk_mtup.probe_size = 0;
	tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
}

/* Do a simple retransmit without using the backoff mechanisms in
 * tcp_timer. This is used for path mtu discovery.
 * The socket is already locked here.
 */
void tcp_simple_retransmit(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	unsigned int mss = tcp_current_mss(sk);
	u32 prior_lost = tp->lost_out;

	tcp_for_write_queue(skb, sk) {
		if (skb == tcp_send_head(sk))
			break;
		if (tcp_skb_seglen(skb) > mss &&
		    !(TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)) {
			if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS) {
				TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_RETRANS;
				tp->retrans_out -= tcp_skb_pcount(skb);
			}
			tcp_skb_mark_lost_uncond_verify(tp, skb);
		}
	}

	tcp_clear_retrans_hints_partial(tp);

	if (prior_lost == tp->lost_out)
		return;

	if (tcp_is_reno(tp))
		tcp_limit_reno_sacked(tp);

	tcp_verify_left_out(tp);

	/* Don't muck with the congestion window here.
	 * Reason is that we do not increase amount of _data_
	 * in network, but units changed and effective
	 * cwnd/ssthresh really reduced now.
	 */
	if (icsk->icsk_ca_state != TCP_CA_Loss) {
		tp->high_seq = tp->snd_nxt;
		tp->snd_ssthresh = tcp_current_ssthresh(sk);
		tp->prior_ssthresh = 0;
		tp->undo_marker = 0;
		tcp_set_ca_state(sk, TCP_CA_Loss);
	}
	tcp_xmit_retransmit_queue(sk);
}
EXPORT_SYMBOL(tcp_simple_retransmit);

/* 进入快速重传/快速恢复阶段 */
static void tcp_enter_recovery(struct sock *sk, bool ece_ack)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int mib_idx;

    /* 根据是否支持SACK，来增加不同的计数器 */
	if (tcp_is_reno(tp))
		mib_idx = LINUX_MIB_TCPRENORECOVERY;
	else
		mib_idx = LINUX_MIB_TCPSACKRECOVERY;

	NET_INC_STATS_BH(sock_net(sk), mib_idx);

	tp->prior_ssthresh = 0;
	tp->undo_marker = tp->snd_una;
	tp->undo_retrans = tp->retrans_out;

    /* 小于TCP_CA_CWR意味着是open或disorder状态 */
	if (inet_csk(sk)->icsk_ca_state < TCP_CA_CWR) {
		if (!ece_ack)
			tp->prior_ssthresh = tcp_current_ssthresh(sk);
		tcp_init_cwnd_reduction(sk, true);  /* 正式进入recovery阶段,初始化函数 */
	}
	tcp_set_ca_state(sk, TCP_CA_Recovery);
}

/* Process an ACK in CA_Loss state. Move to CA_Open if lost data are
 * recovered or spurious. Otherwise retransmits more on partial ACKs.
 */
static void tcp_process_loss(struct sock *sk, int flag, bool is_dupack)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
    /* 判断loss是否被完全恢复了 */
	bool recovered = !before(tp->snd_una, tp->high_seq);

	if (tp->frto) { /* F-RTO RFC5682 sec 3.1 (sack enhanced version). */
        /* 如果收到的第一个ACK包，确认了未重传过的数据，则判定为spurious rto */
		if (flag & FLAG_ORIG_SACK_ACKED) {
			/* Step 3.b. A timeout is spurious if not all data are
			 * lost, i.e., never-retransmitted data are (s)acked.
			 */
			tcp_try_undo_loss(sk, true);
			return;
		}
        /* 如果没有发送新数据，说明这还是FRTO机制收到的第一个ACK包，
         * 如果这个包是一个dupack，则判定为真实的rto */
		if (after(tp->snd_nxt, tp->high_seq) &&
		    (flag & FLAG_DATA_SACKED || is_dupack)) {
			tp->frto = 0; /* Loss was real: 2nd part of step 3.a */
        /* 如果snd_una前移了，但是并没有完全恢复，在FRTO机制中，会选择发送新的数据包 */
		} else if (flag & FLAG_SND_UNA_ADVANCED && !recovered) {
			tp->high_seq = tp->snd_nxt;
			__tcp_push_pending_frames(sk, tcp_current_mss(sk),
						  TCP_NAGLE_OFF);
            /* 只有成功的发送了新的数据包才会进入FRTO的后续判断 */
			if (after(tp->snd_nxt, tp->high_seq))
				return; /* Step 2.b */
            /* 没发送成功数据，只好真实的进入RTO流程，放弃FRTO机制 */
			tp->frto = 0;
		}
	}

    /* 如果loss已经被完全恢复了，则undo recovery */
	if (recovered) {
		/* F-RTO RFC5682 sec 3.1 step 2.a and 1st part of step 3.a */
		icsk->icsk_retransmits = 0;
		tcp_try_undo_recovery(sk);
		return;
	}
	if (flag & FLAG_DATA_ACKED)
		icsk->icsk_retransmits = 0;
	if (tcp_is_reno(tp)) {
		/* A Reno DUPACK means new data in F-RTO step 2.b above are
		 * delivered. Lower inflight to clock out (re)tranmissions.
		 */
		if (after(tp->snd_nxt, tp->high_seq) && is_dupack)
			tcp_add_reno_sack(sk);  /* 增加dupack计数器 */
		else if (flag & FLAG_SND_UNA_ADVANCED)
			tcp_reset_reno_sack(tp);    /* 重置dupack计数器 */
	}
	if (tcp_try_undo_loss(sk, false))
		return;

    /* 如果没能通过FRTO机制判断出spurious，则正常的RTO重传数据 */
	tcp_xmit_retransmit_queue(sk);
}

/* Process an event, which can update packets-in-flight not trivially.
 * Main goal of this function is to calculate new estimate for left_out,
 * taking into account both packets sitting in receiver's buffer and
 * packets lost by network.
 *
 * Besides that it does CWND reduction, when packet loss is detected
 * and changes state of machine.
 *
 * It does _not_ decide what to send, it is made in function
 * tcp_xmit_retransmit_queue().
 */
static void tcp_fastretrans_alert(struct sock *sk, int pkts_acked,
				  int prior_sacked, int prior_packets,
				  bool is_dupack, int flag)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int do_lost = is_dupack || ((flag & FLAG_DATA_SACKED) &&
				    (tcp_fackets_out(tp) > tp->reordering));
	int newly_acked_sacked = 0;
	int fast_rexmit = 0;

	if (WARN_ON(!tp->packets_out && tp->sacked_out))
		tp->sacked_out = 0;
	if (WARN_ON(!tp->sacked_out && tp->fackets_out))
		tp->fackets_out = 0;

	/* Now state machine starts.
	 * A. ECE, hence prohibit cwnd undoing, the reduction is required. */
	if (flag & FLAG_ECE)
		tp->prior_ssthresh = 0;

	/* B. In all the states check for reneging SACKs. */
	if (tcp_check_sack_reneging(sk, flag))
		return;

	/* C. Check consistency of the current state. */
	tcp_verify_left_out(tp);

	/* D. Check state exit conditions. State can be terminated
	 *    when high_seq is ACKed. */
	if (icsk->icsk_ca_state == TCP_CA_Open) {
		WARN_ON(tp->retrans_out != 0);
		tp->retrans_stamp = 0;
	} else if (!before(tp->snd_una, tp->high_seq)) {
		switch (icsk->icsk_ca_state) {
		case TCP_CA_CWR:
			/* CWR is to be held something *above* high_seq
			 * is ACKed for CWR bit to reach receiver. */
			if (tp->snd_una != tp->high_seq) {
				tcp_end_cwnd_reduction(sk);
				tcp_set_ca_state(sk, TCP_CA_Open);
			}
			break;

		case TCP_CA_Recovery:
			if (tcp_is_reno(tp))
				tcp_reset_reno_sack(tp);
			if (tcp_try_undo_recovery(sk))
				return;
			tcp_end_cwnd_reduction(sk);
			break;
		}
	}

	/* E. Process state. */
	switch (icsk->icsk_ca_state) {
	case TCP_CA_Recovery:
		if (!(flag & FLAG_SND_UNA_ADVANCED)) {
			if (tcp_is_reno(tp) && is_dupack)
				tcp_add_reno_sack(sk);
		} else
			do_lost = tcp_try_undo_partial(sk, pkts_acked);
		newly_acked_sacked = prior_packets - tp->packets_out +
				     tp->sacked_out - prior_sacked;
		break;
	case TCP_CA_Loss:
		tcp_process_loss(sk, flag, is_dupack);
		if (icsk->icsk_ca_state != TCP_CA_Open)
			return;
		/* Fall through to processing in Open state. */
	default:
		if (tcp_is_reno(tp)) {
			if (flag & FLAG_SND_UNA_ADVANCED)
				tcp_reset_reno_sack(tp);
			if (is_dupack)
				tcp_add_reno_sack(sk);
		}
		newly_acked_sacked = prior_packets - tp->packets_out +
				     tp->sacked_out - prior_sacked;

		if (icsk->icsk_ca_state <= TCP_CA_Disorder)
			tcp_try_undo_dsack(sk);

		if (!tcp_time_to_recover(sk, flag)) {
			tcp_try_to_open(sk, flag, newly_acked_sacked);
			return;
		}

		/* MTU probe failure: don't reduce cwnd */
		if (icsk->icsk_ca_state < TCP_CA_CWR &&
		    icsk->icsk_mtup.probe_size &&
		    tp->snd_una == tp->mtu_probe.probe_seq_start) {
			tcp_mtup_probe_failed(sk);
			/* Restores the reduction we did in tcp_mtup_probe() */
			tp->snd_cwnd++;
			tcp_simple_retransmit(sk);
			return;
		}

		/* Otherwise enter Recovery state */
		tcp_enter_recovery(sk, (flag & FLAG_ECE));
		fast_rexmit = 1;
	}

	if (do_lost || (tcp_is_fack(tp) && tcp_head_timedout(sk)))
		tcp_update_scoreboard(sk, fast_rexmit);
	tcp_cwnd_reduction(sk, newly_acked_sacked, fast_rexmit);
	tcp_xmit_retransmit_queue(sk);
}

/* 获得一个有效的rtt sample后，更新srtt, rttvar,和rto */
void tcp_valid_rtt_meas(struct sock *sk, u32 seq_rtt)
{
    /* 更新srtt, rttvar */
	tcp_rtt_estimator(sk, seq_rtt);
    /* 更新rto */
	tcp_set_rto(sk);
    /* icsk_backoff是rto timer用于进行指数回避的值 */
	inet_csk(sk)->icsk_backoff = 0;
}
EXPORT_SYMBOL(tcp_valid_rtt_meas);

/* Read draft-ietf-tcplw-high-performance before mucking
 * with this code. (Supersedes RFC1323)
 */
static void tcp_ack_saw_tstamp(struct sock *sk, int flag)
{
	/* RTTM Rule: A TSecr value received in a segment is used to
	 * update the averaged RTT measurement only if the segment
	 * acknowledges some new data, i.e., only if it advances the
	 * left edge of the send window.
	 *
	 * See draft-ietf-tcplw-high-performance-00, section 3.3.
	 * 1998/04/10 Andrey V. Savochkin <saw@msu.ru>
	 *
	 * Changed: reset backoff as soon as we see the first valid sample.
	 * If we do not, we get strongly overestimated rto. With timestamps
	 * samples are accepted even from very old segments: f.e., when rtt=1
	 * increases to 8, we retransmit 5 times and after 8 seconds delayed
	 * answer arrives rto becomes 120 seconds! If at least one of segments
	 * in window is lost... Voila.	 			--ANK (010210)
	 */
	struct tcp_sock *tp = tcp_sk(sk);

    /* 如果timestamp可用，则用tcp_time_stamp - tsecr得到有效的rtt sample */
	tcp_valid_rtt_meas(sk, tcp_time_stamp - tp->rx_opt.rcv_tsecr);
}

static void tcp_ack_no_tstamp(struct sock *sk, u32 seq_rtt, int flag)
{
	/* We don't have a timestamp. Can only use
	 * packets that are not retransmitted to determine
	 * rtt estimates. Also, we must not reset the
	 * backoff for rto until we get a non-retransmitted
	 * packet. This allows us to deal with a situation
	 * where the network delay has increased suddenly.
	 * I.e. Karn's algorithm. (SIGCOMM '87, p5.)
	 */
    /* 不使用重传包进行rtt采样，已经有上层调用函数保证了，
     * 这里再次更严谨的判断，是为了避免调用tcp_valid_rtt_meas()重置icsk_backoff值 */
	if (flag & FLAG_RETRANS_DATA_ACKED)
		return;

	tcp_valid_rtt_meas(sk, seq_rtt);
}

static inline void tcp_ack_update_rtt(struct sock *sk, const int flag,
				      const s32 seq_rtt)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	/* Note that peer MAY send zero echo. In this case it is ignored. (rfc1323) */
    /* 如果timestamp协商成功，并且也收到了非0的tsecr值，则使用timestamp信息计算RTT */
	if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr)
		tcp_ack_saw_tstamp(sk, flag);
    /* 如果未开启timestamp，seq_rtt也是一个合法的值，那么也能更新rtt
     * -- 上层调用函数负责计算seq_rtt：
     *  1. 如果这个数据包未重传过，则发送skb时记录的when值还可以用一用，用timestamp - when就得到seq_rtt
     *  2. 如果数据包重传过，则无法放心的使用when值计算rtt，故放弃这个计算rtt的机会，设置seq_rtt为 -1 */
	else if (seq_rtt >= 0)
		tcp_ack_no_tstamp(sk, seq_rtt, flag);
}

/* 调用拥塞避免算法，来增大cwnd。比如如果使用CUBIC算法，则上tcp_cubic.c中找.cong_avoid对应的函数 */
static void tcp_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	icsk->icsk_ca_ops->cong_avoid(sk, ack, in_flight);
	tcp_sk(sk)->snd_cwnd_stamp = tcp_time_stamp;
}

/* Restart timer after forward progress on connection.
 * RFC2988 recommends to restart timer to now+rto.
 */
/* 重设重传超时计时器 */
void tcp_rearm_rto(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* If the retrans timer is currently being used by Fast Open
	 * for SYN-ACK retrans purpose, stay put.
	 */
    /* 如果计时器正用于fast open机制，则不重设 */
	if (tp->fastopen_rsk)
		return;

	if (!tp->packets_out) {
        /* 如果已经没有数据包在外面了，则可以清楚rto timer，不用重设了 */
		inet_csk_clear_xmit_timer(sk, ICSK_TIME_RETRANS);
	} else {
		u32 rto = inet_csk(sk)->icsk_rto;
		/* Offset the time elapsed after installing regular RTO */
        /* 这一段的内在含义就是：如果rto时间已经被ER或TLP用掉了一部分，
         * 但是又没有用完，还剩下多少，rto就被还原成多少，所以叫rearm_rto */
		if (icsk->icsk_pending == ICSK_TIME_EARLY_RETRANS ||
		    icsk->icsk_pending == ICSK_TIME_LOSS_PROBE) {
			struct sk_buff *skb = tcp_write_queue_head(sk);
			const u32 rto_time_stamp = TCP_SKB_CB(skb)->when + rto;
			s32 delta = (s32)(rto_time_stamp - tcp_time_stamp);
			/* delta may not be positive if the socket is locked
			 * when the retrans timer fires and is rescheduled.
			 */
			if (delta > 0)
				rto = delta;
		}
        /* 设置重传计时器，计时器的用途为ICSK_TIME_RETRANS即rto timer */
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS, rto,
					  TCP_RTO_MAX);
	}
}

/* This function is called when the delayed ER timer fires. TCP enters
 * fast recovery and performs fast-retransmit.
 */
/* 所谓delayed ER timer就是Linux选择等待稍微delay一下,避免spurious retrans的一种措施 */
void tcp_resume_early_retransmit(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

    /* 当ER timer超时后，进入快速重传，并重设RTO超时 */
	tcp_rearm_rto(sk);  

	/* Stop if ER is disabled after the delayed ER timer is scheduled */
	if (!tp->do_early_retrans)
		return;

    /* 进入TCP_CA_Recovery阶段，即快速重传/快速恢复阶段 */
	tcp_enter_recovery(sk, false);
    /* 更新scoreboard，将判断为丢包的skb标记为已丢失状态，即TCPCB_LOST状态
     * 具体的判断为丢包的方法要根据是否支持sack, 是否支持fack来定 */
	tcp_update_scoreboard(sk, 1);
    /* 更新重传队列的scoreboard后，可以根据各个skb的标记进行重传了，下面这个函数会遍历重传队列 */
	tcp_xmit_retransmit_queue(sk);
}

/* If we get here, the whole TSO packet has not been acked. */
static u32 tcp_tso_acked(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 packets_acked;

	BUG_ON(!after(TCP_SKB_CB(skb)->end_seq, tp->snd_una));

	packets_acked = tcp_skb_pcount(skb);
	if (tcp_trim_head(sk, skb, tp->snd_una - TCP_SKB_CB(skb)->seq))
		return 0;
	packets_acked -= tcp_skb_pcount(skb);

	if (packets_acked) {
		BUG_ON(tcp_skb_pcount(skb) == 0);
		BUG_ON(!before(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq));
	}

	return packets_acked;
}

/* Remove acknowledged frames from the retransmission queue. If our packet
 * is before the ack sequence we can discard it as it's confirmed to have
 * arrived at the other end.
 */
static int tcp_clean_rtx_queue(struct sock *sk, int prior_fackets,
			       u32 prior_snd_una)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct sk_buff *skb;
	u32 now = tcp_time_stamp;
	int fully_acked = true;
	int flag = 0;
	u32 pkts_acked = 0;
	u32 reord = tp->packets_out;
	u32 prior_sacked = tp->sacked_out;
	s32 seq_rtt = -1;
	s32 ca_seq_rtt = -1;
	ktime_t last_ackt = net_invalid_timestamp();

	while ((skb = tcp_write_queue_head(sk)) && skb != tcp_send_head(sk)) {
		struct tcp_skb_cb *scb = TCP_SKB_CB(skb);
		u32 acked_pcount;
		u8 sacked = scb->sacked;

		/* Determine how many packets and what bytes were acked, tso and else */
		if (after(scb->end_seq, tp->snd_una)) {
			if (tcp_skb_pcount(skb) == 1 ||
			    !after(tp->snd_una, scb->seq))
				break;

			acked_pcount = tcp_tso_acked(sk, skb);
			if (!acked_pcount)
				break;

			fully_acked = false;
		} else {
			acked_pcount = tcp_skb_pcount(skb);
		}

		if (sacked & TCPCB_RETRANS) {
			if (sacked & TCPCB_SACKED_RETRANS)
				tp->retrans_out -= acked_pcount;
			flag |= FLAG_RETRANS_DATA_ACKED;
			ca_seq_rtt = -1;
			seq_rtt = -1;
		} else {
			ca_seq_rtt = now - scb->when;
			last_ackt = skb->tstamp;
			if (seq_rtt < 0) {
				seq_rtt = ca_seq_rtt;
			}
			if (!(sacked & TCPCB_SACKED_ACKED))
				reord = min(pkts_acked, reord);
			if (!after(scb->end_seq, tp->high_seq))
				flag |= FLAG_ORIG_SACK_ACKED;
		}

		if (sacked & TCPCB_SACKED_ACKED)
			tp->sacked_out -= acked_pcount;
		if (sacked & TCPCB_LOST)
			tp->lost_out -= acked_pcount;

		tp->packets_out -= acked_pcount;
		pkts_acked += acked_pcount;

		/* Initial outgoing SYN's get put onto the write_queue
		 * just like anything else we transmit.  It is not
		 * true data, and if we misinform our callers that
		 * this ACK acks real data, we will erroneously exit
		 * connection startup slow start one packet too
		 * quickly.  This is severely frowned upon behavior.
		 */
		if (!(scb->tcp_flags & TCPHDR_SYN)) {
			flag |= FLAG_DATA_ACKED;
		} else {
			flag |= FLAG_SYN_ACKED;
			tp->retrans_stamp = 0;
		}

		if (!fully_acked)
			break;

		tcp_unlink_write_queue(skb, sk);
		sk_wmem_free_skb(sk, skb);
		tp->scoreboard_skb_hint = NULL;
		if (skb == tp->retransmit_skb_hint)
			tp->retransmit_skb_hint = NULL;
		if (skb == tp->lost_skb_hint)
			tp->lost_skb_hint = NULL;
	}

	if (likely(between(tp->snd_up, prior_snd_una, tp->snd_una)))
		tp->snd_up = tp->snd_una;

	if (skb && (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED))
		flag |= FLAG_SACK_RENEGING;

	if (flag & FLAG_ACKED) {
		const struct tcp_congestion_ops *ca_ops
			= inet_csk(sk)->icsk_ca_ops;

		if (unlikely(icsk->icsk_mtup.probe_size &&
			     !after(tp->mtu_probe.probe_seq_end, tp->snd_una))) {
			tcp_mtup_probe_success(sk);
		}

        /* 当收到一个ACK后，会更新rtt sample，进而更新srtt, rttvar, 最终更新rto */
		tcp_ack_update_rtt(sk, flag, seq_rtt);
        /* 重新启动超时计时器,使用刚更新后的rto值 */
		tcp_rearm_rto(sk);

		if (tcp_is_reno(tp)) {
			tcp_remove_reno_sacks(sk, pkts_acked);
		} else {
			int delta;

			/* Non-retransmitted hole got filled? That's reordering */
			if (reord < prior_fackets)
				tcp_update_reordering(sk, tp->fackets_out - reord, 0);

			delta = tcp_is_fack(tp) ? pkts_acked :
						  prior_sacked - tp->sacked_out;
			tp->lost_cnt_hint -= min(tp->lost_cnt_hint, delta);
		}

		tp->fackets_out -= min(pkts_acked, tp->fackets_out);

		if (ca_ops->pkts_acked) {
			s32 rtt_us = -1;

			/* Is the ACK triggering packet unambiguous? */
			if (!(flag & FLAG_RETRANS_DATA_ACKED)) {
				/* High resolution needed and available? */
				if (ca_ops->flags & TCP_CONG_RTT_STAMP &&
				    !ktime_equal(last_ackt,
						 net_invalid_timestamp()))
					rtt_us = ktime_us_delta(ktime_get_real(),
								last_ackt);
				else if (ca_seq_rtt >= 0)
					rtt_us = jiffies_to_usecs(ca_seq_rtt);
			}

			ca_ops->pkts_acked(sk, pkts_acked, rtt_us);
		}
	}

#if FASTRETRANS_DEBUG > 0
	WARN_ON((int)tp->sacked_out < 0);
	WARN_ON((int)tp->lost_out < 0);
	WARN_ON((int)tp->retrans_out < 0);
	if (!tp->packets_out && tcp_is_sack(tp)) {
		icsk = inet_csk(sk);
		if (tp->lost_out) {
			pr_debug("Leak l=%u %d\n",
				 tp->lost_out, icsk->icsk_ca_state);
			tp->lost_out = 0;
		}
		if (tp->sacked_out) {
			pr_debug("Leak s=%u %d\n",
				 tp->sacked_out, icsk->icsk_ca_state);
			tp->sacked_out = 0;
		}
		if (tp->retrans_out) {
			pr_debug("Leak r=%u %d\n",
				 tp->retrans_out, icsk->icsk_ca_state);
			tp->retrans_out = 0;
		}
	}
#endif
	return flag;
}

/* 在处理一个ack后，如果接收窗口足够大，则要清除zero window probe timer;
 * 否则，就需要重设zero window probe timer */
static void tcp_ack_probe(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	/* Was it a usable window open? */
    /* 如果发送队列中的第一个SKB的尾序号 <= 被接收窗口允许的序号，则放弃zero window probe */
	if (!after(TCP_SKB_CB(tcp_send_head(sk))->end_seq, tcp_wnd_end(tp))) {
		icsk->icsk_backoff = 0;
		inet_csk_clear_xmit_timer(sk, ICSK_TIME_PROBE0);
		/* Socket must be waked up by subsequent tcp_data_snd_check().
		 * This function is not for random using!
		 */
	} else {
        /* 可见zero window probe timer也是指数回避的形式增长的 */
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
					  min(icsk->icsk_rto << icsk->icsk_backoff, TCP_RTO_MAX),
					  TCP_RTO_MAX);
	}
}

/* 根据flag判断一个ACK包是否可疑 */
static inline bool tcp_ack_is_dubious(const struct sock *sk, const int flag)
{
    /* FLAG_NOT_DUP包括： (FLAG_DATA|FLAG_WIN_UPDATE|FLAG_ACKED)
     * 如果这个ACK，不携带数据，不更新窗口，也不确认数据，那这肯定是一个值得怀疑的ACK
     * FLAG_NOT_DUP只要不为0，则可以认为这个ACK不是dupack(NOT DUP) */
	return !(flag & FLAG_NOT_DUP) ||        
           (flag & FLAG_CA_ALERT) ||        /* 如果有拥塞信号(sack或ece),则要谨慎处理 */
		   inet_csk(sk)->icsk_ca_state != TCP_CA_Open;  /* 不是Open状态，自然要谨慎处理ACK */
}

/* 判断是否可以使用拥塞避免增大cwnd */
static inline bool tcp_may_raise_cwnd(const struct sock *sk, const int flag)
{
	const struct tcp_sock *tp = tcp_sk(sk);
            /* 1. 如果携带了ECE标记，并且cwnd已经不小于ssthresh，则不能增大cwnd */
	return (!(flag & FLAG_ECE) || tp->snd_cwnd < tp->snd_ssthresh) && 
            /* 如果已经处于cwnd_reduction状态，则不可能又执行增大cwnd的操作，故不执行拥塞避免 */
		   !tcp_in_cwnd_reduction(sk);
}

/* Check that window update is acceptable.
 * The function assumes that snd_una<=ack<=snd_next.
 */
/* 判断确认号ack是否更新发送窗口 */
/* TODO-DONE: 这里的window update，到底是发送窗口更新，还是接收窗口更新？
 * 更新发送窗口！！！ */
static inline bool tcp_may_update_window(const struct tcp_sock *tp,
					const u32 ack, const u32 ack_seq,
					const u32 nwin)
{
	return	after(ack, tp->snd_una) ||      /* 如果ack大于snd_una，则有新数据被确认了，显然会更新发送窗口 */
        /* 如果接收包的确认序号大于上一次更新发送窗口时记录的序号，则更新发送窗口 */
		after(ack_seq, tp->snd_wl1) ||      
        /* 如果本地没有往对端发数据，但是接收包中的receive window值变大了，则需要更新发送窗口 */
		(ack_seq == tp->snd_wl1 && nwin > tp->snd_wnd);
}

/* Update our send window.
 *
 * Window update algorithm, described in RFC793/RFC1122 (used in linux-2.2
 * and in FreeBSD. NetBSD's one is even worse.) is wrong.
 */
static int tcp_ack_update_window(struct sock *sk, const struct sk_buff *skb, u32 ack,
				 u32 ack_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int flag = 0;
	u32 nwin = ntohs(tcp_hdr(skb)->window);

    /* 如果不带SYN标记，则还要考虑window scale值 */
	if (likely(!tcp_hdr(skb)->syn))
		nwin <<= tp->rx_opt.snd_wscale;

    /* tcp_may_update_window()负责判断是否需要更新发送窗口，返回true表示需要更新 */
	if (tcp_may_update_window(tp, ack, ack_seq, nwin)) {
		flag |= FLAG_WIN_UPDATE;    /* 给flag打上更新发送窗口的标记 */
		tcp_update_wl(tp, ack_seq); /* 记录导致发送窗口被更新的ACK包序号 */

		if (tp->snd_wnd != nwin) {
			tp->snd_wnd = nwin;

			/* Note, it is the only place, where
			 * fast path is recovered for sending TCP.
			 */
            /* 首部预测标志与接收窗口大小有关，因此需要重新计算 */
			tp->pred_flags = 0;
            /* 检查是否能进入fast path,如果可以则计算pred_flags */
			tcp_fast_path_check(sk);

			if (nwin > tp->max_window) {
				tp->max_window = nwin;  /* max_window记录都是收到过的最大接收窗口 */
				tcp_sync_mss(sk, inet_csk(sk)->icsk_pmtu_cookie);   /* 更新MSS */
			}
		}
	}

	tp->snd_una = ack;  /* 更新发送窗口的一个重要标记，就是更新snd_una值 */

	return flag;
}

/* RFC 5961 7 [ACK Throttling] */
/* 如果在now的粒度(1s?)内，收到的有问题的ack个数不超过sysctl_tcp_challenge_ack_limit(默认值100)个，则发送一个challenge_ack */
static void tcp_send_challenge_ack(struct sock *sk)
{
	/* unprotected vars, we dont care of overwrites */
    /* 为数不多的使用static变量的位置，提醒一下 */
	static u32 challenge_timestamp;
	static unsigned int challenge_count;
    /* TODO： 确认now的粒度具体是多少，怎么算出来的 */
	u32 now = jiffies / HZ;

    /* now的粒度是1s?，如果now == challenge_timestmps，意味着tcp_send_changenge_ack是在1s内被调用 */
	if (now != challenge_timestamp) {
        /* 如果过了1s,则重设challenge_timestamp和challenge_count */
		challenge_timestamp = now;
		challenge_count = 0;
	}
	if (++challenge_count <= sysctl_tcp_challenge_ack_limit) {
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPCHALLENGEACK);
		tcp_send_ack(sk);
	}
}

/* 更新rx_opt.ts_recent，并记录更新时间 */
static void tcp_store_ts_recent(struct tcp_sock *tp)
{
	tp->rx_opt.ts_recent = tp->rx_opt.rcv_tsval;
	tp->rx_opt.ts_recent_stamp = get_seconds();
}

/* 更新ts_recent */
static void tcp_replace_ts_recent(struct tcp_sock *tp, u32 seq)
{
    /* 只有开启了timestamp选项 并且seq <= tp->rcv_wup时才会更新
     * 如果数据都是按序到达的，则seq == tp->rcv_wup
     * 但如果发生乱序，乱序包收到的时候不会更新ts_recent，知道按序包收到时才会更新ts_recent ！ */
	if (tp->rx_opt.saw_tstamp && !after(seq, tp->rcv_wup)) {
		/* PAWS bug workaround wrt. ACK frames, the PAWS discard
		 * extra check below makes sure this can only happen
		 * for pure ACK frames.  -DaveM
		 *
		 * Not only, also it occurs for expired timestamps.
		 */

		if (tcp_paws_check(&tp->rx_opt, 0))
			tcp_store_ts_recent(tp);
	}
}

/* This routine deals with acks during a TLP episode.
 * Ref: loss detection algorithm in draft-dukkipati-tcpm-tcp-loss-probe.
 */
static void tcp_process_tlp_ack(struct sock *sk, u32 ack, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);
    /* 判断这个ACK是否是由TLP包触发的，并且是一个dupack，即多余发送的 */
	bool is_tlp_dupack = (ack == tp->tlp_high_seq) &&       /* 如果ack序号就是TLP包发送时的snd_nxt */
                /* 以下flag都没有设置：
                 * FLAG_SND_UNA_ADVANCED 未设置表示这个ACK包并没有移动SND_UNA,即没有确认新的数据！dupack的重要标记
                 * FLAG_NOT_DUP 未设置表示 
                 *      1. 这个ACK不携带数据
                 *      2. 不是一个window update包（window update包本质上是一个不带数据的dupack包
                 *      3. 确认ACK没有确认过新的数据，dupack的重要标记
                 * FLAG_DATA_SACKED 未设置表示没有携带任何新SACK块 */
			     !(flag & (FLAG_SND_UNA_ADVANCED |
				       FLAG_NOT_DUP | FLAG_DATA_SACKED));

	/* Mark the end of TLP episode on receiving TLP dupack or when
	 * ack is after tlp_high_seq.
	 */
    /* 如果判断出TLP探测包是完全多余的，则直接返回 */
	if (is_tlp_dupack) {
		tp->tlp_high_seq = 0;
		return;
	}

    /* 如果确认的新的数据 */
	if (after(ack, tp->tlp_high_seq)) {
		tp->tlp_high_seq = 0;
		/* Don't reduce cwnd if DSACK arrives for TLP retrans. */
        /* 如果发现DSACK，也意味着TLP是多余，*/
		if (!(flag & FLAG_DSACKING_ACK)) {
            /* 下面这么一大圈，重点就是降了cwnd： ssthresh = 0.7 * cwnd; cwnd = ssthresh */
			tcp_init_cwnd_reduction(sk, true);
			tcp_set_ca_state(sk, TCP_CA_CWR);
			tcp_end_cwnd_reduction(sk);
			tcp_set_ca_state(sk, TCP_CA_Open);
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPLOSSPROBERECOVERY); /* 通过TLP技术恢复了一次尾丢包则加1 */
		}
	}
}

/* This routine deals with incoming acks, but not outgoing ones. */
static int tcp_ack(struct sock *sk, const struct sk_buff *skb, int flag)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 prior_snd_una = tp->snd_una;
    /* TCP_SKB_CB(skb)->seq 与 TCP_SKB_CB(skb)->ack_seq的区别在哪？
     * 根据原有注释的字面意思理解：前者是该TCP ACK包的起始序号, 后者是被确认的序号
     * 但还是解释的不够透彻
     * 理解：TCP_SKB_CB(skb)中的seq是对端的seq，ack_seq是对端确认本端发过去的数据，
     * 所以本地处理这个ACK包时，需要将ack_seq解释成这个ACK包按序确认了本地的那个序号(ack) 
     * 而TCP_SKB_CB(skb)->seq是对端对这个ACK包中数据的序号，这个序号是需要本端发送给对端的确认数据
     * 一句话总结：下面等号左边的ack_seq是对端的序号，ack是本地的序号
     * 更新：标准的解释ack_seq是序号，ack是确认号*/
	u32 ack_seq = TCP_SKB_CB(skb)->seq;     
	u32 ack = TCP_SKB_CB(skb)->ack_seq;
	bool is_dupack = false;
	u32 prior_in_flight;
	u32 prior_fackets;
	int prior_packets = tp->packets_out;
	int prior_sacked = tp->sacked_out;
	int pkts_acked = 0;
	int previous_packets_out = 0;

	/* If the ack is older than previous acks
	 * then we can probably ignore it.
	 */
    /* 如果被确认的数据号比处理这个ACK包之前的snd_una还小，则这个ACK需要被丢弃 */
	if (before(ack, prior_snd_una)) {
		/* RFC 5961 5.2 [Blind Data Injection Attack].[Mitigation] */
        /* max_window是看到过的对端发送过来的最大的接收窗口大小
         * 如果ack序号比snd_una - max_window都小，就怀疑这个有人在进行 blind data injection攻击了 */
		if (before(ack, prior_snd_una - tp->max_window)) {
			tcp_send_challenge_ack(sk);     /* 发送一个challenge_ack给对端 */
			return -1;
		}
		goto old_ack;
	}

	/* If the ack includes data we haven't sent yet, discard
	 * this segment (RFC793 Section 3.9).
	 */
	if (after(ack, tp->snd_nxt))
		goto invalid_ack;

    /* 理解后续代码是要记得：之后的处理中，ack序号已经满足合法范围 [prior_snd_una, tp->snd_nxt] */

	if (icsk->icsk_pending == ICSK_TIME_EARLY_RETRANS ||    /* 如果之前启动了ER timer，收到ACK后重新设置RTO timer */
	    icsk->icsk_pending == ICSK_TIME_LOSS_PROBE)         /* 如果之前启动了PTO，收到ACK后重新设置RTO timer */
		tcp_rearm_rto(sk);

    /* 如果ack序号大于处理这个ACK包之前的snd_una，则标记有新数据被确认掉了，也就是snd_una需要前移了(advanced) */
	if (after(ack, prior_snd_una))
		flag |= FLAG_SND_UNA_ADVANCED;

	prior_fackets = tp->fackets_out;
	prior_in_flight = tcp_packets_in_flight(tp);

	/* ts_recent update must be made after we are sure that the packet
	 * is in window.
	 */
	if (flag & FLAG_UPDATE_TS_RECENT)
		tcp_replace_ts_recent(tp, TCP_SKB_CB(skb)->seq);

    /* 如果不是慢速路径，并且ack大于处理该ACK包之前的snd_una, 进而被认定为: pure forward advance */
    /* TODO：根据目前的了解，不是FLAG_SLOWPATH不就是Fast path了吗 ？ */
	if (!(flag & FLAG_SLOWPATH) && after(ack, prior_snd_una)) {
		/* Window is constant, pure forward advance.
		 * No more checks are required.
		 * Note, we use the fact that SND.UNA>=SND.WL2.
		 */
		tcp_update_wl(tp, ack_seq); /* 记录导致发送窗口被更新的ACK包序号 */
		tp->snd_una = ack;          /* 更新snd_una, 也可理解为发送窗口左端前移 */
		flag |= FLAG_WIN_UPDATE;    /* 发送窗口左端前移，也就意味着发送窗口被更新 */

        /* in sequence ack: 按序到达，且确认了新数据的ACK 通知拥塞控制算法 */
        /* 目前也就发现westwood算法里面关心这个拥塞事件 */
		tcp_ca_event(sk, CA_EVENT_FAST_ACK);    

        /* 至此可知，TCPHPACKS的含义是：在tcp_ack()处理逻辑中，
         * 如果不是在慢速路径，并且这个ACK更新了发送窗口，则该计数器加1 */
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPHPACKS);
	} else {
        /* 如果ACK包中有数据，标记FLAG_DATA, 否则增加TCPPUREACKS计数器的值 */
		if (ack_seq != TCP_SKB_CB(skb)->end_seq)
			flag |= FLAG_DATA;
		else
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPPUREACKS);

        /* 如果更新了发送窗口，则返回FLAG_WIN_UPDATE给flag
         * 注意：snd_una变量会在tcp_ack_update_window()中更新!!! */
		flag |= tcp_ack_update_window(sk, skb, ack, ack_seq);

        /* 如果检测到了SACK block，则在重传队列中做好标记, 即更新scoreboard */
		if (TCP_SKB_CB(skb)->sacked)
			flag |= tcp_sacktag_write_queue(sk, skb, prior_snd_una);

        /* 查看ACK是否携带ECE标志，且标示合法 */
		if (TCP_ECN_rcv_ecn_echo(tp, tcp_hdr(skb)))
			flag |= FLAG_ECE;

		tcp_ca_event(sk, CA_EVENT_SLOW_ACK);    /* 该拥塞事件，也是只有在westwood中关心 */
	}

	/* We passed data and got it acked, remove any soft error
	 * log. Something worked...
	 */
	sk->sk_err_soft = 0;
	icsk->icsk_probes_out = 0;
	tp->rcv_tstamp = tcp_time_stamp;
    /* 如果packets_out为0，即没有发送且未被按序确认的数据包
     * 则进入no_queue逻辑。 
     * DONE： no_queue内在含义是什么？
     * no_queue表示发送队列为空, 也就是packets_out == 0 */
	if (!prior_packets)
		goto no_queue;

	/* See if we can take anything off of the retransmit queue. */
    /* 这个地方为什么要重新拿一次packets_out ?
     * 目前知道tp->snd_una可能会改变，但是暂时还没找到使用改变后的snd_una去更新packets_out的代码
     * 查找代码发现，tp->packets_out仅会在发送了数据包的情况下改变，也就是说上面某个过程中会发送数据包？
     *
     * 更新：previous_packets_out变量的引入请查看该patch: https://github.com/torvalds/linux/commit/35f079ebbc860dcd1cca70890c9c8d59c1145525
     * 根本的原因就是在下面这个调用序列中，packets_out可能被改变！
     * tcp_sacktag_write_queue -> tcp_sacktag_write_queue -> tcp_sacktag_walk -> tcp_match_skb_to_sack -> tcp_fragment -> tcp_adjust_pcount */
	previous_packets_out = tp->packets_out;
    /* 删除重传队列中已经确认的数据段 */
	flag |= tcp_clean_rtx_queue(sk, prior_fackets, prior_snd_una);

    /* 计算此次被ACKed的数据包个数 */
	pkts_acked = previous_packets_out - tp->packets_out;

    /* 检查这是否是一个可疑的ACK：dupack, 带SACK，或者不是Open状态 */
    /* 一旦发现可疑的ACK，则意味着要么已经处于非open状态，要么就是刚收到拥塞信号，即将离开Open状态 */
	if (tcp_ack_is_dubious(sk, flag)) {
		/* Advance CWND, if state allows this. */
        /* 如果此时想进行拥塞避免算法增大cwnd，必须满足:
         * 1. 这个ACK确认了新的数据
         * 2. 通过检查flag，满足增大cwnd的条件，具体看tcp_may_raise_cwnd() */
		if ((flag & FLAG_DATA_ACKED) && tcp_may_raise_cwnd(sk, flag))
			tcp_cong_avoid(sk, ack, prior_in_flight);
        /* 判断是否是一个dupack，最完整的逻辑, NOT_DUP是dupack的充分条件，但不是必要条件 */
		is_dupack = !(flag & (FLAG_SND_UNA_ADVANCED | FLAG_NOT_DUP));
        /* 进入TCP的拥塞状态机，处理相关的拥塞状态 */
		tcp_fastretrans_alert(sk, pkts_acked, prior_sacked,
				      prior_packets, is_dupack, flag);
	} else {
        /* 如果不是可以的ACK，则只要ACK确认了新数据，则可以考虑增加cwnd了
         * 这里的新数据并不包含SYN标记，尽管SYN标记也占用一个序号
         * 所以Linux里面使用了FLAG_DATA_ACKED来表示数据的确认， FLAG_SYN_ACKED来表示SYN被确认了 */
		if (flag & FLAG_DATA_ACKED)
			tcp_cong_avoid(sk, ack, prior_in_flight);
	}

    /* 如果之前进行了TLP探测，则还要进行TLP相关处理 */
	if (tp->tlp_high_seq)
		tcp_process_tlp_ack(sk, ack, flag);

    /* 如果ACK确认了新的数据(按序确认的数据，SYN段，SACK数据)
     * 或者收到的ACK不是重复的，
     * 则确定该传输控制块的输出路由缓存项是有效的 */
	if ((flag & FLAG_FORWARD_PROGRESS) || !(flag & FLAG_NOT_DUP)) {
		struct dst_entry *dst = __sk_dst_get(sk);
		if (dst)
			dst_confirm(dst);
	}

    /* 尝试安装PTO
     * 安装失败，则说明还没到需要安装PTO的时候，会正常的使用RTO timer */
	if (icsk->icsk_pending == ICSK_TIME_RETRANS)
		tcp_schedule_loss_probe(sk);
	return 1;

no_queue:
	/* If data was DSACKed, see if we can undo a cwnd reduction. */
    /* 尽管此时packets_out为0，但是如果发现了DSACK信息还是要关注的 */
	if (flag & FLAG_DSACKING_ACK)
		tcp_fastretrans_alert(sk, pkts_acked, prior_sacked,
				      prior_packets, is_dupack, flag);
	/* If this ack opens up a zero window, clear backoff.  It was
	 * being used to time the probes, and is probably far higher than
	 * it needs to be for normal retransmission.
	 */
    /* 如果packets_out为0，但实际却有数据要发送，则可能是由于对端之前通知了一个zero window导致的
     * 因此需要看看是否能清除zero window probe timer(recevie window更新的够大了)
     * 当然，如果receive window更新的还是不够，那么就得重设 timer了 */
	if (tcp_send_head(sk))
		tcp_ack_probe(sk);

    /* 如果之前进行了TLP探测，则还要进行TLP相关处理
     * 为什么要在packets_out == 0的时候还处理呢？因为在这条路径上也还是需要关闭TLP episode的 */
	if (tp->tlp_high_seq)
		tcp_process_tlp_ack(sk, ack, flag);
	return 1;

invalid_ack:
	SOCK_DEBUG(sk, "Ack %u after %u:%u\n", ack, tp->snd_una, tp->snd_nxt);
	return -1;

old_ack:
	/* If data was SACKed, tag it and see if we should send more data.
	 * If data was DSACKed, see if we can undo a cwnd reduction.
	 */
    /* 尽管这个包的确认号是比较老的，但是如果携带SACK信息，则还是要看看能不能用上的 */
    /* 1. 这里的old_ack，也不是太老，ack序号也是大于snd_una - max_window的，更老的ACK有tcp_send_challenge_ack去处理
     * 什么情况下这种SACK信息是有用的呢？TODO:需要找个一个例子 */
	if (TCP_SKB_CB(skb)->sacked) {
		flag |= tcp_sacktag_write_queue(sk, skb, prior_snd_una);
		tcp_fastretrans_alert(sk, pkts_acked, prior_sacked,
				      prior_packets, is_dupack, flag);
	}

	SOCK_DEBUG(sk, "Ack %u before %u:%u\n", ack, tp->snd_una, tp->snd_nxt);
	return 0;
}

/* Look for tcp options. Normally only called on SYN and SYNACK packets.
 * But, this can also be called on packets in the established flow when
 * the fast version below fails.
 */
void tcp_parse_options(const struct sk_buff *skb,
		       struct tcp_options_received *opt_rx, int estab,
		       struct tcp_fastopen_cookie *foc)
{
	const unsigned char *ptr;
	const struct tcphdr *th = tcp_hdr(skb);
    /* 获得选项部分的长度 */
	int length = (th->doff * 4) - sizeof(struct tcphdr);

    /* ptr指向选项部分的首字节 */
	ptr = (const unsigned char *)(th + 1);
	opt_rx->saw_tstamp = 0;

    /* length在解析过程中，表示还有多少字节的option要被解析 */
	while (length > 0) {
        /* 先获option的类型 */
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:    /* 选项结束标记 */
			return;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
            /* pading的字节，跳过即可 */
			length--;
			continue;
		default:
            /* 再获取option的长度 */
			opsize = *ptr++;
            /* option类型加长度这两个域就至少2字节了，如果opsize小于2，
             * 则说明肯定是不合法的选项, 进而放弃解析选项 */
			if (opsize < 2) /* "silly options" */
				return;
            /* opsize超过剩余的length也肯定是非法的 */
			if (opsize > length)
				return;	/* don't parse partial options */
			switch (opcode) {
			case TCPOPT_MSS:    
                /* MSS大小的协商仅发生在：非established状态下收到的SYN包 */
				if (opsize == TCPOLEN_MSS && th->syn && !estab) {
					u16 in_mss = get_unaligned_be16(ptr);
                    /* mss要取用户限制的值和option中指定值的较小值 */
                    /* 在tcp_check_req()函数调用时未执行user_mss */
					if (in_mss) {
						if (opt_rx->user_mss &&
						    opt_rx->user_mss < in_mss)
							in_mss = opt_rx->user_mss;
						opt_rx->mss_clamp = in_mss;
					}
				}
				break;
			case TCPOPT_WINDOW: 
                /* window scaling 选项, 解析条件也必须带syn标记，非established状态
                 * 同时系统还必须开了window_scaling选项 */
				if (opsize == TCPOLEN_WINDOW && th->syn &&
				    !estab && sysctl_tcp_window_scaling) {
					__u8 snd_wscale = *(__u8 *)ptr;
					opt_rx->wscale_ok = 1;
                    /* window scale值最大是14，具体解释可参考RFC，
                     * 简单的解释就是 th->window << win_scale 不宜超过th->seq能表示的范围 */
					if (snd_wscale > 14) {
						net_info_ratelimited("%s: Illegal window scaling value %d >14 received\n",
								     __func__,
								     snd_wscale);
						snd_wscale = 14;
					}
					opt_rx->snd_wscale = snd_wscale;
				}
				break;
			case TCPOPT_TIMESTAMP:  
                /* 解析timestamp选项
                 * 解析的条件：
                 * 1. 要么在SYN包中已经见过该选项，并且由于本地也开了timestamp选项，已经将tstamp_ok置为1了
                 * 2. 要么是第一次见到该选项(收到第一个SYN包)，只有在本地也开了timestamp的情况下，
                 *    才将saw_tstamp置1(进而会将tstamp_ok置1) */
				if ((opsize == TCPOLEN_TIMESTAMP) &&
				    ((estab && opt_rx->tstamp_ok) ||
				     (!estab && sysctl_tcp_timestamps))) {
					opt_rx->saw_tstamp = 1;     /* 表示在最近收到的对端发过来的包中看到"过"timestamp */
					opt_rx->rcv_tsval = get_unaligned_be32(ptr);
                    /* 一个完整的timestap选项，肯定带tsecr部分，但在SYN包中，由于它是第一个数据包，
                     * 所以syn包中的tsecr值是0 
                     * 因此解析一下也无妨 */
					opt_rx->rcv_tsecr = get_unaligned_be32(ptr + 4);
				}
				break;
			case TCPOPT_SACK_PERM:  
                /* 解析SACK-Permitted 选项 */
				if (opsize == TCPOLEN_SACK_PERM &&  /* 长度为2 */
                    th->syn &&      /* 只在SYN包中解析 */
				    !estab &&       /* 在流未建立时才解析 */
                    sysctl_tcp_sack) {  /* 是否开启选项，默认开启 */
					opt_rx->sack_ok = TCP_SACK_SEEN;
					tcp_sack_reset(opt_rx);
				}
				break;

			case TCPOPT_SACK:
                /* 检查SACK option的正确性和合法性，并设置sacked标记 */
				if ((opsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK)) &&
				   !((opsize - TCPOLEN_SACK_BASE) % TCPOLEN_SACK_PERBLOCK) &&
				   opt_rx->sack_ok) {
                    /* 这里sacked被赋值为SACK option在TCP包中偏移
                     * 为后续直接找到SACK option进行解析提供方便 */
					TCP_SKB_CB(skb)->sacked = (ptr - 2) - (unsigned char *)th;
				}
				break;
#ifdef CONFIG_TCP_MD5SIG
			case TCPOPT_MD5SIG:
				/*
				 * The MD5 Hash has already been
				 * checked (see tcp_v{4,6}_do_rcv()).
				 */
				break;
#endif
			case TCPOPT_EXP:
                /* 实验性的选项 */
				/* Fast Open option shares code 254 using a
				 * 16 bits magic number. It's valid only in
				 * SYN or SYN-ACK with an even size.
				 */
				if (opsize < TCPOLEN_EXP_FASTOPEN_BASE ||
				    get_unaligned_be16(ptr) != TCPOPT_FASTOPEN_MAGIC ||
				    foc == NULL || !th->syn || (opsize & 1))
					break;
				foc->len = opsize - TCPOLEN_EXP_FASTOPEN_BASE;
				if (foc->len >= TCP_FASTOPEN_COOKIE_MIN &&
				    foc->len <= TCP_FASTOPEN_COOKIE_MAX)
					memcpy(foc->val, ptr + 2, foc->len);
				else if (foc->len != 0)
					foc->len = -1;
				break;

			}
            /* 移动ptr，继续解析剩余的option */
			ptr += opsize-2;
			length -= opsize;
		}
	}
}
EXPORT_SYMBOL(tcp_parse_options);

/* 解析一个对齐了的timestamp选项，成功返回true */
static bool tcp_parse_aligned_timestamp(struct tcp_sock *tp, const struct tcphdr *th)
{
    /* th指向tcp包头的起始位置，而tcphdr结构体是不包含TCP选项的。
     * 先(th + 1)就让th指向了tcp选项部分的起始位置 */
	const __be32 *ptr = (const __be32 *)(th + 1);

    /* 如果ptr指向的内容 == 0x 0101 080a, 则这是一个对其了的timestamp option */
	if (*ptr == htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16)
			  | (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP)) {
		tp->rx_opt.saw_tstamp = 1;  /* 标记见到了timestamp */
		++ptr;
		tp->rx_opt.rcv_tsval = ntohl(*ptr);     /* 解析对端发过来的timestamp值 */
		++ptr;
        /* 解析本地发出去的timestamp值 */
        /* TODO: tp->tsoffset 是干嘛用的？ 是RFC中提到的一个random的避免被推测出本地时间的值吗 ？ */
		tp->rx_opt.rcv_tsecr = ntohl(*ptr) - tp->tsoffset;
		return true;
	}
	return false;
}

/* Fast parse options. This hopes to only see timestamps.
 * If it is wrong it falls back on tcp_parse_options().
 */
static bool tcp_fast_parse_options(const struct sk_buff *skb,
				   const struct tcphdr *th, struct tcp_sock *tp)
{
	/* In the spirit of fast parsing, compare doff directly to constant
	 * values.  Because equality is used, short doff can be ignored here.
	 */
	if (th->doff == (sizeof(*th) / 4)) {
		tp->rx_opt.saw_tstamp = 0;
		return false;
	} else if (tp->rx_opt.tstamp_ok &&
		   th->doff == ((sizeof(*th) + TCPOLEN_TSTAMP_ALIGNED) / 4)) {
		if (tcp_parse_aligned_timestamp(tp, th))
			return true;
	}

	tcp_parse_options(skb, &tp->rx_opt, 1, NULL);
	if (tp->rx_opt.saw_tstamp)
		tp->rx_opt.rcv_tsecr -= tp->tsoffset;

	return true;
}

#ifdef CONFIG_TCP_MD5SIG
/*
 * Parse MD5 Signature option
 */
const u8 *tcp_parse_md5sig_option(const struct tcphdr *th)
{
	int length = (th->doff << 2) - sizeof(*th);
	const u8 *ptr = (const u8 *)(th + 1);

	/* If the TCP option is too short, we can short cut */
	if (length < TCPOLEN_MD5SIG)
		return NULL;

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch(opcode) {
		case TCPOPT_EOL:
			return NULL;
		case TCPOPT_NOP:
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2 || opsize > length)
				return NULL;
			if (opcode == TCPOPT_MD5SIG)
				return opsize == TCPOLEN_MD5SIG ? ptr : NULL;
		}
		ptr += opsize - 2;
		length -= opsize;
	}
	return NULL;
}
EXPORT_SYMBOL(tcp_parse_md5sig_option);
#endif

/* Sorry, PAWS as specified is broken wrt. pure-ACKs -DaveM
 *
 * It is not fatal. If this ACK does _not_ change critical state (seqs, window)
 * it can pass through stack. So, the following predicate verifies that
 * this segment is not used for anything but congestion avoidance or
 * fast retransmit. Moreover, we even are able to eliminate most of such
 * second order effects, if we apply some small "replay" window (~RTO)
 * to timestamp space.
 *
 * All these measures still do not guarantee that we reject wrapped ACKs
 * on networks with high bandwidth, when sequence space is recycled fastly,
 * but it guarantees that such events will be very rare and do not affect
 * connection seriously. This doesn't look nice, but alas, PAWS is really
 * buggy extension.
 *
 * [ Later note. Even worse! It is buggy for segments _with_ data. RFC
 * states that events when retransmit arrives after original data are rare.
 * It is a blatant lie. VJ forgot about fast retransmit! 8)8) It is
 * the biggest problem on large power networks even with minor reordering.
 * OK, let's give it small replay window. If peer clock is even 1hz, it is safe
 * up to bandwidth of 18Gigabit/sec. 8) ]
 */

/* 判断是否是乱序的ACK， 如果是乱序则返回true */
/* 如果判定为乱序的ACK，则通过PAWS检查，不会丢弃该数据包 */
/* 该函数的引入目的：
 *      在快速重传机制被触发后，会连续触发大量的dupack。
 *      如果这些dupack之间发生乱序，在没有该函数判断情况下，就会被discard掉。
 *      从而影响快速重传阶段能收到的dupack数量
 */
static int tcp_disordered_ack(const struct sock *sk, const struct sk_buff *skb)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct tcphdr *th = tcp_hdr(skb);
	u32 seq = TCP_SKB_CB(skb)->seq;     /* skb数据包的起始seq */
	u32 ack = TCP_SKB_CB(skb)->ack_seq; /* skb数据包所确认的序号 */

    /* 如果同时满足以下注释的四个条件，则判定为乱序ACK */
	return (/* 1. Pure ACK with correct sequence number. */
		(th->ack && seq == TCP_SKB_CB(skb)->end_seq && seq == tp->rcv_nxt) &&

		/* 2. ... and duplicate ACK. */
		ack == tp->snd_una &&

		/* 3. ... and does not update window. */
		!tcp_may_update_window(tp, ack, seq, ntohs(th->window) << tp->rx_opt.snd_wscale) &&

		/* 4. ... and sits in replay window. */
		(s32)(tp->rx_opt.ts_recent - tp->rx_opt.rcv_tsval) <= (inet_csk(sk)->icsk_rto * 1024) / HZ);
}

/* PAWS检查，如需丢弃则返回true */
static inline bool tcp_paws_discard(const struct sock *sk,
				   const struct sk_buff *skb)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return !tcp_paws_check(&tp->rx_opt, TCP_PAWS_WINDOW) &&
	       !tcp_disordered_ack(sk, skb);
}

/* Check segment sequence number for validity.
 *
 * Segment controls are considered valid, if the segment
 * fits to the window after truncation to the window. Acceptability
 * of data (and SYN, FIN, of course) is checked separately.
 * See tcp_data_queue(), for example.
 *
 * Also, controls (RST is main one) are accepted using RCV.WUP instead
 * of RCV.NXT. Peer still did not advance his SND.UNA when we
 * delayed ACK, so that hisSND.UNA<=ourRCV.WUP.
 * (borrowed from freebsd)
 */

/* 根据序号，检查合法性。 */
/* 从判断条件可以看出，如果一个数据包的起始序号在[rcv_nxt, rcv_nxt + rcv_wnd]区间，
 * 但end_seq > rcv_nxt + rcv_wnd也是合法的。
 */
static inline bool tcp_sequence(const struct tcp_sock *tp, u32 seq, u32 end_seq)
{
    /* 如果skb尾序号 < rcv_wup,则该数据包太老了，非法，返回false */
	return	!before(end_seq, tp->rcv_wup) &&
        /* 如果skb起始序号 > rcv_nxt + rcv_wnd，则该序号太新了，非法，返回false */
		!after(seq, tp->rcv_nxt + tcp_receive_window(tp));
}

/* When we get a reset we do this. */
/* 一条TCP被reset后，会根据状态返回不同的错误信息 */
void tcp_reset(struct sock *sk)
{
	/* We want the right error as BSD sees it (and indeed as we do). */
	switch (sk->sk_state) {
	case TCP_SYN_SENT:
		sk->sk_err = ECONNREFUSED;
		break;
	case TCP_CLOSE_WAIT:
		sk->sk_err = EPIPE;
		break;
	case TCP_CLOSE:
		return;
	default:
		sk->sk_err = ECONNRESET;
	}
	/* This barrier is coupled with smp_rmb() in tcp_poll() */
	smp_wmb();

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_error_report(sk);

	tcp_done(sk);
}

/*
 * 	Process the FIN bit. This now behaves as it is supposed to work
 *	and the FIN takes effect when it is validly part of sequence
 *	space. Not before when we get holes.
 *
 *	If we are ESTABLISHED, a received fin moves us to CLOSE-WAIT
 *	(and thence onto LAST-ACK and finally, CLOSE, we never enter
 *	TIME-WAIT)
 *
 *	If we are in FINWAIT-1, a received FIN indicates simultaneous
 *	close and we go into CLOSING (and later onto TIME-WAIT)
 *
 *	If we are in FINWAIT-2, a received FIN moves us to TIME-WAIT.
 */
static void tcp_fin(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	inet_csk_schedule_ack(sk);

	sk->sk_shutdown |= RCV_SHUTDOWN;
	sock_set_flag(sk, SOCK_DONE);

	switch (sk->sk_state) {
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
		/* Move to CLOSE_WAIT */
		tcp_set_state(sk, TCP_CLOSE_WAIT);
		inet_csk(sk)->icsk_ack.pingpong = 1;
		break;

	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
		/* Received a retransmission of the FIN, do
		 * nothing.
		 */
		break;
	case TCP_LAST_ACK:
		/* RFC793: Remain in the LAST-ACK state. */
		break;

	case TCP_FIN_WAIT1:
		/* This case occurs when a simultaneous close
		 * happens, we must ack the received FIN and
		 * enter the CLOSING state.
		 */
		tcp_send_ack(sk);
		tcp_set_state(sk, TCP_CLOSING);
		break;
	case TCP_FIN_WAIT2:
		/* Received a FIN -- send ACK and enter TIME_WAIT. */
		tcp_send_ack(sk);
		tcp_time_wait(sk, TCP_TIME_WAIT, 0);
		break;
	default:
		/* Only TCP_LISTEN and TCP_CLOSE are left, in these
		 * cases we should never reach this piece of code.
		 */
		pr_err("%s: Impossible, sk->sk_state=%d\n",
		       __func__, sk->sk_state);
		break;
	}

	/* It _is_ possible, that we have something out-of-order _after_ FIN.
	 * Probably, we should reset in this case. For now drop them.
	 */
	__skb_queue_purge(&tp->out_of_order_queue);
	if (tcp_is_sack(tp))
		tcp_sack_reset(&tp->rx_opt);
	sk_mem_reclaim(sk);

	if (!sock_flag(sk, SOCK_DEAD)) {
		sk->sk_state_change(sk);

		/* Do not send POLL_HUP for half duplex close. */
		if (sk->sk_shutdown == SHUTDOWN_MASK ||
		    sk->sk_state == TCP_CLOSE)
			sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_HUP);
		else
			sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
	}
}

static inline bool tcp_sack_extend(struct tcp_sack_block *sp, u32 seq,
				  u32 end_seq)
{
	if (!after(seq, sp->end_seq) && !after(sp->start_seq, end_seq)) {
		if (before(seq, sp->start_seq))
			sp->start_seq = seq;
		if (after(end_seq, sp->end_seq))
			sp->end_seq = end_seq;
		return true;
	}
	return false;
}

static void tcp_dsack_set(struct sock *sk, u32 seq, u32 end_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tcp_is_sack(tp) && sysctl_tcp_dsack) {
		int mib_idx;

        /* 如果发送的dsack序号小于rcv_nxt，说明这是一个已经
         * 按序收到的数据包的重复包，进而增加oldsent计数器 */
		if (before(seq, tp->rcv_nxt))
			mib_idx = LINUX_MIB_TCPDSACKOLDSENT;
		else
            /* 反之增加ofosent计数器，即out of order */
			mib_idx = LINUX_MIB_TCPDSACKOFOSENT;

		NET_INC_STATS_BH(sock_net(sk), mib_idx);

		tp->rx_opt.dsack = 1;
		tp->duplicate_sack[0].start_seq = seq;
		tp->duplicate_sack[0].end_seq = end_seq;
	}
}

static void tcp_dsack_extend(struct sock *sk, u32 seq, u32 end_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tp->rx_opt.dsack)
		tcp_dsack_set(sk, seq, end_seq);
	else
		tcp_sack_extend(tp->duplicate_sack, seq, end_seq);
}

static void tcp_send_dupack(struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
	    before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKLOST);
		tcp_enter_quickack_mode(sk);

		if (tcp_is_sack(tp) && sysctl_tcp_dsack) {
			u32 end_seq = TCP_SKB_CB(skb)->end_seq;

			if (after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt))
				end_seq = tp->rcv_nxt;
			tcp_dsack_set(sk, TCP_SKB_CB(skb)->seq, end_seq);
		}
	}

	tcp_send_ack(sk);
}

/* These routines update the SACK block as out-of-order packets arrive or
 * in-order packets close up the sequence space.
 */
static void tcp_sack_maybe_coalesce(struct tcp_sock *tp)
{
	int this_sack;
	struct tcp_sack_block *sp = &tp->selective_acks[0];
	struct tcp_sack_block *swalk = sp + 1;

	/* See if the recent change to the first SACK eats into
	 * or hits the sequence space of other SACK blocks, if so coalesce.
	 */
	for (this_sack = 1; this_sack < tp->rx_opt.num_sacks;) {
		if (tcp_sack_extend(sp, swalk->start_seq, swalk->end_seq)) {
			int i;

			/* Zap SWALK, by moving every further SACK up by one slot.
			 * Decrease num_sacks.
			 */
			tp->rx_opt.num_sacks--;
			for (i = this_sack; i < tp->rx_opt.num_sacks; i++)
				sp[i] = sp[i + 1];
			continue;
		}
		this_sack++, swalk++;
	}
}

static void tcp_sack_new_ofo_skb(struct sock *sk, u32 seq, u32 end_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_sack_block *sp = &tp->selective_acks[0];
	int cur_sacks = tp->rx_opt.num_sacks;
	int this_sack;

	if (!cur_sacks)
		goto new_sack;

	for (this_sack = 0; this_sack < cur_sacks; this_sack++, sp++) {
		if (tcp_sack_extend(sp, seq, end_seq)) {
			/* Rotate this_sack to the first one. */
			for (; this_sack > 0; this_sack--, sp--)
				swap(*sp, *(sp - 1));
			if (cur_sacks > 1)
				tcp_sack_maybe_coalesce(tp);
			return;
		}
	}

	/* Could not find an adjacent existing SACK, build a new one,
	 * put it at the front, and shift everyone else down.  We
	 * always know there is at least one SACK present already here.
	 *
	 * If the sack array is full, forget about the last one.
	 */
	if (this_sack >= TCP_NUM_SACKS) {
		this_sack--;
		tp->rx_opt.num_sacks--;
		sp--;
	}
	for (; this_sack > 0; this_sack--, sp--)
		*sp = *(sp - 1);

new_sack:
	/* Build the new head SACK, and we're done. */
	sp->start_seq = seq;
	sp->end_seq = end_seq;
	tp->rx_opt.num_sacks++;
}

/* RCV.NXT advances, some SACKs should be eaten. */

static void tcp_sack_remove(struct tcp_sock *tp)
{
	struct tcp_sack_block *sp = &tp->selective_acks[0];
	int num_sacks = tp->rx_opt.num_sacks;
	int this_sack;

	/* Empty ofo queue, hence, all the SACKs are eaten. Clear. */
	if (skb_queue_empty(&tp->out_of_order_queue)) {
		tp->rx_opt.num_sacks = 0;
		return;
	}

	for (this_sack = 0; this_sack < num_sacks;) {
		/* Check if the start of the sack is covered by RCV.NXT. */
		if (!before(tp->rcv_nxt, sp->start_seq)) {
			int i;

			/* RCV.NXT must cover all the block! */
			WARN_ON(before(tp->rcv_nxt, sp->end_seq));

			/* Zap this SACK, by moving forward any other SACKS. */
			for (i=this_sack+1; i < num_sacks; i++)
				tp->selective_acks[i-1] = tp->selective_acks[i];
			num_sacks--;
			continue;
		}
		this_sack++;
		sp++;
	}
	tp->rx_opt.num_sacks = num_sacks;
}

/* This one checks to see if we can put data from the
 * out_of_order queue into the receive_queue.
 */
static void tcp_ofo_queue(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 dsack_high = tp->rcv_nxt;
	struct sk_buff *skb;

	while ((skb = skb_peek(&tp->out_of_order_queue)) != NULL) {
		if (after(TCP_SKB_CB(skb)->seq, tp->rcv_nxt))
			break;

		if (before(TCP_SKB_CB(skb)->seq, dsack_high)) {
			__u32 dsack = dsack_high;
			if (before(TCP_SKB_CB(skb)->end_seq, dsack_high))
				dsack_high = TCP_SKB_CB(skb)->end_seq;
			tcp_dsack_extend(sk, TCP_SKB_CB(skb)->seq, dsack);
		}

		if (!after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt)) {
			SOCK_DEBUG(sk, "ofo packet was already received\n");
			__skb_unlink(skb, &tp->out_of_order_queue);
			__kfree_skb(skb);
			continue;
		}
		SOCK_DEBUG(sk, "ofo requeuing : rcv_next %X seq %X - %X\n",
			   tp->rcv_nxt, TCP_SKB_CB(skb)->seq,
			   TCP_SKB_CB(skb)->end_seq);

		__skb_unlink(skb, &tp->out_of_order_queue);
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		if (tcp_hdr(skb)->fin)
			tcp_fin(sk);
	}
}

static bool tcp_prune_ofo_queue(struct sock *sk);
static int tcp_prune_queue(struct sock *sk);

/* 检查是否可以分配新的rmem，
 * 返回0表示可以，返回-1表示不可以
 */
static int tcp_try_rmem_schedule(struct sock *sk, struct sk_buff *skb,
				 unsigned int size)
{
    /* 如果sk_rmem_alloc不超过sk_rcvbuf，并且也没有超过tcp_rmem限制, 则直接返回0 */
	if (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf ||
	    !sk_rmem_schedule(sk, skb, size)) {

        /* 如果修剪接收队列后，依然mem不足，只好返回-1表示不可以分配新内存了, 从而会导致数据包被丢弃  */
		if (tcp_prune_queue(sk) < 0)
			return -1;

        /* 如果是整体内存超过tcp_rmem限制 */
		if (!sk_rmem_schedule(sk, skb, size)) {
            /* 如果OFO为空，没有mem腾出来了，只能返回-1 */
			if (!tcp_prune_ofo_queue(sk))
				return -1;

            /* 上面会腾出OFO空间，所以还要判断一次。如果腾空OFO后，还是无法满足条件，也是只能返回-1 */
			if (!sk_rmem_schedule(sk, skb, size))
				return -1;
		}
	}
	return 0;
}

/**
 * tcp_try_coalesce - try to merge skb to prior one
 * @sk: socket
 * @to: prior buffer
 * @from: buffer to add in queue
 * @fragstolen: pointer to boolean
 *
 * Before queueing skb @from after @to, try to merge them
 * to reduce overall memory use and queue lengths, if cost is small.
 * Packets in ofo or receive queues can stay a long time.
 * Better try to coalesce them right now to avoid future collapses.
 * Returns true if caller should free @from instead of queueing it
 */
/* 尝试将from合并到to中，合并成功返回true, 失败返回false */
static bool tcp_try_coalesce(struct sock *sk,
			     struct sk_buff *to,
			     struct sk_buff *from,
			     bool *fragstolen)
{
	int delta;

	*fragstolen = false;

	if (tcp_hdr(from)->fin)
		return false;

	/* Its possible this segment overlaps with prior segment in queue */
	if (TCP_SKB_CB(from)->seq != TCP_SKB_CB(to)->end_seq)
		return false;

	if (!skb_try_coalesce(to, from, fragstolen, &delta))
		return false;

	atomic_add(delta, &sk->sk_rmem_alloc);
	sk_mem_charge(sk, delta);
    /* TCP接收缓存合并skb成功的次数 */
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPRCVCOALESCE);
	TCP_SKB_CB(to)->end_seq = TCP_SKB_CB(from)->end_seq;
	TCP_SKB_CB(to)->ack_seq = TCP_SKB_CB(from)->ack_seq;
	return true;
}

static void tcp_data_queue_ofo(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb1;
	u32 seq, end_seq;

	TCP_ECN_check_ce(tp, skb);

	if (unlikely(tcp_try_rmem_schedule(sk, skb, skb->truesize))) {
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPOFODROP);
		__kfree_skb(skb);
		return;
	}

	/* Disable header prediction. */
	tp->pred_flags = 0;
	inet_csk_schedule_ack(sk);

	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPOFOQUEUE);
	SOCK_DEBUG(sk, "out of order segment: rcv_next %X seq %X - %X\n",
		   tp->rcv_nxt, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq);

	skb1 = skb_peek_tail(&tp->out_of_order_queue);
	if (!skb1) {
		/* Initial out of order segment, build 1 SACK. */
		if (tcp_is_sack(tp)) {
			tp->rx_opt.num_sacks = 1;
			tp->selective_acks[0].start_seq = TCP_SKB_CB(skb)->seq;
			tp->selective_acks[0].end_seq =
						TCP_SKB_CB(skb)->end_seq;
		}
		__skb_queue_head(&tp->out_of_order_queue, skb);
		goto end;
	}

	seq = TCP_SKB_CB(skb)->seq;
	end_seq = TCP_SKB_CB(skb)->end_seq;

	if (seq == TCP_SKB_CB(skb1)->end_seq) {
		bool fragstolen;

		if (!tcp_try_coalesce(sk, skb1, skb, &fragstolen)) {
			__skb_queue_after(&tp->out_of_order_queue, skb1, skb);
		} else {
			kfree_skb_partial(skb, fragstolen);
			skb = NULL;
		}

		if (!tp->rx_opt.num_sacks ||
		    tp->selective_acks[0].end_seq != seq)
			goto add_sack;

		/* Common case: data arrive in order after hole. */
		tp->selective_acks[0].end_seq = end_seq;
		goto end;
	}

	/* Find place to insert this segment. */
	while (1) {
		if (!after(TCP_SKB_CB(skb1)->seq, seq))
			break;
		if (skb_queue_is_first(&tp->out_of_order_queue, skb1)) {
			skb1 = NULL;
			break;
		}
		skb1 = skb_queue_prev(&tp->out_of_order_queue, skb1);
	}

	/* Do skb overlap to previous one? */
	if (skb1 && before(seq, TCP_SKB_CB(skb1)->end_seq)) {
		if (!after(end_seq, TCP_SKB_CB(skb1)->end_seq)) {
			/* All the bits are present. Drop. */
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPOFOMERGE);
			__kfree_skb(skb);
			skb = NULL;
			tcp_dsack_set(sk, seq, end_seq);
			goto add_sack;
		}
		if (after(seq, TCP_SKB_CB(skb1)->seq)) {
			/* Partial overlap. */
			tcp_dsack_set(sk, seq,
				      TCP_SKB_CB(skb1)->end_seq);
		} else {
			if (skb_queue_is_first(&tp->out_of_order_queue,
					       skb1))
				skb1 = NULL;
			else
				skb1 = skb_queue_prev(
					&tp->out_of_order_queue,
					skb1);
		}
	}
	if (!skb1)
		__skb_queue_head(&tp->out_of_order_queue, skb);
	else
		__skb_queue_after(&tp->out_of_order_queue, skb1, skb);

	/* And clean segments covered by new one as whole. */
	while (!skb_queue_is_last(&tp->out_of_order_queue, skb)) {
		skb1 = skb_queue_next(&tp->out_of_order_queue, skb);

		if (!after(end_seq, TCP_SKB_CB(skb1)->seq))
			break;
		if (before(end_seq, TCP_SKB_CB(skb1)->end_seq)) {
			tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
					 end_seq);
			break;
		}
		__skb_unlink(skb1, &tp->out_of_order_queue);
		tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
				 TCP_SKB_CB(skb1)->end_seq);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPOFOMERGE);
		__kfree_skb(skb1);
	}

add_sack:
	if (tcp_is_sack(tp))
		tcp_sack_new_ofo_skb(sk, seq, end_seq);
end:
	if (skb)
		skb_set_owner_r(skb, sk);
}

/* 将数据放到receive queue中 */
static int __must_check tcp_queue_rcv(struct sock *sk, struct sk_buff *skb, int hdrlen,
		  bool *fragstolen)
{
	int eaten;
	struct sk_buff *tail = skb_peek_tail(&sk->sk_receive_queue);

	__skb_pull(skb, hdrlen);
    /* 尝试将skb合并到tail中 */
	eaten = (tail &&
		 tcp_try_coalesce(sk, tail, skb, fragstolen)) ? 1 : 0;
	tcp_sk(sk)->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
    /* 如果没有成功，则将skb挂到receive queue中 */
	if (!eaten) {
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		skb_set_owner_r(skb, sk);
	}
	return eaten;
}

int tcp_send_rcvq(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct sk_buff *skb = NULL;
	struct tcphdr *th;
	bool fragstolen;

	if (size == 0)
		return 0;

	skb = alloc_skb(size + sizeof(*th), sk->sk_allocation);
	if (!skb)
		goto err;

	if (tcp_try_rmem_schedule(sk, skb, size + sizeof(*th)))
		goto err_free;

	th = (struct tcphdr *)skb_put(skb, sizeof(*th));
	skb_reset_transport_header(skb);
	memset(th, 0, sizeof(*th));

	if (memcpy_fromiovec(skb_put(skb, size), msg->msg_iov, size))
		goto err_free;

	TCP_SKB_CB(skb)->seq = tcp_sk(sk)->rcv_nxt;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(skb)->seq + size;
	TCP_SKB_CB(skb)->ack_seq = tcp_sk(sk)->snd_una - 1;

	if (tcp_queue_rcv(sk, skb, sizeof(*th), &fragstolen)) {
		WARN_ON_ONCE(fragstolen); /* should not happen */
		__kfree_skb(skb);
	}
	return size;

err_free:
	kfree_skb(skb);
err:
	return -ENOMEM;
}

/* 将skb放入接收队列或out-of-order队列 */
static void tcp_data_queue(struct sock *sk, struct sk_buff *skb)
{
	const struct tcphdr *th = tcp_hdr(skb);
	struct tcp_sock *tp = tcp_sk(sk);
	int eaten = -1;
	bool fragstolen = false;

    /* 如果不带数据，直接丢弃 */
	if (TCP_SKB_CB(skb)->seq == TCP_SKB_CB(skb)->end_seq)
		goto drop;

	skb_dst_drop(skb);
    /* 去掉TCP包头的数据，仅保留应用层数据 */
	__skb_pull(skb, th->doff * 4);

	TCP_ECN_accept_cwr(tp, skb);

	tp->rx_opt.dsack = 0;

	/*  Queue data for delivery to the user.
	 *  Packets in sequence go to the receive queue.
	 *  Out of sequence packets to the out_of_order_queue.
	 */
    /* 如果是按序到达的数据，则放入receive queue */
	if (TCP_SKB_CB(skb)->seq == tp->rcv_nxt) {
        /* 如果数据超过了接收窗口的限制，则要特殊处理：进入quickack模式，调度一个ack，并且把数据丢掉 */
		if (tcp_receive_window(tp) == 0)
			goto out_of_window;

		/* Ok. In sequence. In window. */
        /* 如果当前process context正在拷贝数据，而且位置也匹配 */
		if (tp->ucopy.task == current &&
		    tp->copied_seq == tp->rcv_nxt && tp->ucopy.len &&
		    sock_owned_by_user(sk) && !tp->urg_data) {
			int chunk = min_t(unsigned int, skb->len,
					  tp->ucopy.len);

			__set_current_state(TASK_RUNNING);

            /* 此时想将数据直接拷贝到用户态，必须把softirq给关了 */
			local_bh_enable();
            /* 将数据拷贝到iovec中 */
			if (!skb_copy_datagram_iovec(skb, 0, tp->ucopy.iov, chunk)) {
				tp->ucopy.len -= chunk;
				tp->copied_seq += chunk;
				eaten = (chunk == skb->len);
				tcp_rcv_space_adjust(sk);
			}
			local_bh_disable();
		}

		if (eaten <= 0) {
queue_and_out:
            /* 如果skb没有被直接拷贝到user space的iovec, 同时分配rmem也失败了，则只好丢弃该skb */
			if (eaten < 0 &&
			    tcp_try_rmem_schedule(sk, skb, skb->truesize))
				goto drop;

			eaten = tcp_queue_rcv(sk, skb, 0, &fragstolen);
		}
		tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		if (skb->len)
			tcp_event_data_recv(sk, skb);
		if (th->fin)
			tcp_fin(sk);

		if (!skb_queue_empty(&tp->out_of_order_queue)) {
			tcp_ofo_queue(sk);

			/* RFC2581. 4.2. SHOULD send immediate ACK, when
			 * gap in queue is filled.
			 */
			if (skb_queue_empty(&tp->out_of_order_queue))
				inet_csk(sk)->icsk_ack.pingpong = 0;
		}

		if (tp->rx_opt.num_sacks)
			tcp_sack_remove(tp);

		tcp_fast_path_check(sk);

		if (eaten > 0)
			kfree_skb_partial(skb, fragstolen);
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_data_ready(sk, 0);
		return;
	}

	if (!after(TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt)) {
		/* A retransmit, 2nd most common case.  Force an immediate ack. */
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKLOST);
		tcp_dsack_set(sk, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq);

out_of_window:
		tcp_enter_quickack_mode(sk);
		inet_csk_schedule_ack(sk);
drop:
		__kfree_skb(skb);
		return;
	}

	/* Out of window. F.e. zero window probe. */
	if (!before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt + tcp_receive_window(tp)))
		goto out_of_window;

	tcp_enter_quickack_mode(sk);

	if (before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt)) {
		/* Partial packet, seq < rcv_next < end_seq */
		SOCK_DEBUG(sk, "partial packet: rcv_next %X seq %X - %X\n",
			   tp->rcv_nxt, TCP_SKB_CB(skb)->seq,
			   TCP_SKB_CB(skb)->end_seq);

		tcp_dsack_set(sk, TCP_SKB_CB(skb)->seq, tp->rcv_nxt);

		/* If window is closed, drop tail of packet. But after
		 * remembering D-SACK for its head made in previous line.
		 */
		if (!tcp_receive_window(tp))
			goto out_of_window;
		goto queue_and_out;
	}

	tcp_data_queue_ofo(sk, skb);
}

/* 场景1： 如果在合并OFO queue时发现，某个skb的数据完全是冗余的，则直接将这个skb从列表中删掉 */
static struct sk_buff *tcp_collapse_one(struct sock *sk, struct sk_buff *skb,
					struct sk_buff_head *list)
{
	struct sk_buff *next = NULL;

	if (!skb_queue_is_last(list, skb))
		next = skb_queue_next(list, skb);

	__skb_unlink(skb, list);
	__kfree_skb(skb);
    /* 该计数器记录某个SKB中的数据完全是冗余，而被删除的次数 */
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPRCVCOLLAPSED);

    /* 返回下一个skb的指针，如果要删除的skb是tail，那么返回NULL */
	return next;
}

/* Collapse contiguous sequence of skbs head..tail with
 * sequence numbers start..end.
 *
 * If tail is NULL, this means until the end of the list.
 *
 * Segments with FIN/SYN are not collapsed (only because this
 * simplifies code)
 */
/* 将序号连续的skb进行合并, 非常耗时的动作！ */
/* TODO: 这个函数不好理解，理解了宏观的流程再来详细分析 */
static void
tcp_collapse(struct sock *sk, struct sk_buff_head *list,
	     struct sk_buff *head, struct sk_buff *tail,
	     u32 start, u32 end)
{
	struct sk_buff *skb, *n;
	bool end_of_skbs;

	/* First, check that queue is collapsible and find
	 * the point where collapsing can be useful. */
	skb = head;
restart:
    /* TODO-DONE: end_of_skbs的含义？
     * 如果为true，表示下面找start的过程中，已经遍历到了end skb，都没有找到可以进行合并的start，
     * 此时可以直接返回了，没有合并的必要了 */
	end_of_skbs = true;
    /* 这个loop的作用：找到可以作为真实的start的序号。
     * 为什么存在这个过程，而不是直接用caller指定的start？
     * 因为有一些skb是不允许collapse的。比如带有SYN或FIN标记的数据包 */
	skb_queue_walk_from_safe(list, skb, n) {
		if (skb == tail)
			break;
		/* No new bits? It is possible on ofo queue. */
		if (!before(start, TCP_SKB_CB(skb)->end_seq)) {
			skb = tcp_collapse_one(sk, skb, list);
            /* 如果使用tcp_collapse_one()删除的skb是tail,说明遍历完了，直接break */
			if (!skb)
				break;
            /* skb已经更新成了新的next,回到skb位置继续找合适的start */
			goto restart;
		}

        /* 确定真实的start的条件 */
		/* The first skb to collapse is:
		 * - not SYN/FIN(条件a) and
		 * - bloated(条件b) or contains data before "start"(条件c) or
		 *   overlaps to the next one.(条件d)
		 */
		if (!tcp_hdr(skb)->syn && !tcp_hdr(skb)->fin && 
            /* 条件b: 如果skb->len连truesize的一半都不到 */
		    (tcp_win_from_space(skb->truesize) > skb->len ||
            /* 条件c:skb的起始序号在start之前， */
		     before(TCP_SKB_CB(skb)->seq, start))) {
			end_of_skbs = false;
			break;
		}

		if (!skb_queue_is_last(list, skb)) {
			struct sk_buff *next = skb_queue_next(list, skb);
			if (next != tail &&
                /* 条件d: skb与next存在overlap */
			    TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(next)->seq) {
				end_of_skbs = false;
				break;
			}
		}

		/* Decided to skip this, advance start seq. */
        /* 如果当前遍历到的skb不满足作为start的条件，则跳过这个skb, 增大start */
		start = TCP_SKB_CB(skb)->end_seq;
	}
    /* 如果所有skb都不满足合并条件，或者带有syn、fin标记，则停止合并 */
	if (end_of_skbs || tcp_hdr(skb)->syn || tcp_hdr(skb)->fin)
		return;

    /* 将[start, end]区间的内容合并 */
	while (before(start, end)) {
		struct sk_buff *nskb;
		unsigned int header = skb_headroom(skb);
		int copy = SKB_MAX_ORDER(header, 0);

		/* Too big header? This can happen with IPv6. */
		if (copy < 0)
			return;
		if (end - start < copy)
			copy = end - start;
        /* 首先会分配一个page作为新的skb内存空间，copy值就表示是这个page内，能放入的数据量 */
		nskb = alloc_skb(copy + header, GFP_ATOMIC);
		if (!nskb)
			return;

        /* 预留MAC头、IP头、TCP头 */
		skb_set_mac_header(nskb, skb_mac_header(skb) - skb->head);
		skb_set_network_header(nskb, (skb_network_header(skb) -
					      skb->head));
		skb_set_transport_header(nskb, (skb_transport_header(skb) -
						skb->head));
		skb_reserve(nskb, header);
        /* 拷贝头部信息 */
		memcpy(nskb->head, skb->head, header);
        /* 拷贝skb control block信息 */
		memcpy(nskb->cb, skb->cb, sizeof(skb->cb));
        /* 在拷贝数据前，seq和end_seq都设置为start */
		TCP_SKB_CB(nskb)->seq = TCP_SKB_CB(nskb)->end_seq = start;
        /* 将新skb插入到当前skb之前 */
		__skb_queue_before(list, skb, nskb);
        /* 设置skb与sk关联，并更新sk->sk_forward_alloc值 */
		skb_set_owner_r(nskb, sk);

		/* Copy data, releasing collapsed skbs. */
		while (copy > 0) {
			int offset = start - TCP_SKB_CB(skb)->seq;
			int size = TCP_SKB_CB(skb)->end_seq - start;

			BUG_ON(offset < 0);
            /* size表示当前skb需要拷贝的数据量 */
			if (size > 0) {
				size = min(copy, size);
				if (skb_copy_bits(skb, offset, skb_put(nskb, size), size))
					BUG();
				TCP_SKB_CB(nskb)->end_seq += size;
                /* 拷贝数据后，更新copy和start */
				copy -= size;
				start += size;
			}
            /* 如果一个skb的数据都拷贝完了，则要将这个skb删除 */
			if (!before(start, TCP_SKB_CB(skb)->end_seq)) {
				skb = tcp_collapse_one(sk, skb, list);
				if (!skb ||
				    skb == tail ||
				    tcp_hdr(skb)->syn ||
				    tcp_hdr(skb)->fin)
					return;
			}
		}
	}
}

/* Collapse ofo queue. Algorithm: select contiguous sequence of skbs
 * and tcp_collapse() them until all the queue is collapsed.
 */
/* 尽量合并OFO queue中的skb */
/* 从遍历过程就可以看出来，这是一个非常耗时的行为 */
static void tcp_collapse_ofo_queue(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = skb_peek(&tp->out_of_order_queue);
	struct sk_buff *head;
	u32 start, end;

	if (skb == NULL)
		return;

	start = TCP_SKB_CB(skb)->seq;
	end = TCP_SKB_CB(skb)->end_seq;
	head = skb;

	for (;;) {
		struct sk_buff *next = NULL;

		if (!skb_queue_is_last(&tp->out_of_order_queue, skb))
			next = skb_queue_next(&tp->out_of_order_queue, skb);
		skb = next;

		/* Segment is terminated when we see gap or when
		 * we are at the end of all the queue. */
        /* 从判断条件中可知，OFO queue是彻底乱序的，后面包的seq是可能小于前面包的seq的 */
		if (!skb ||
		    after(TCP_SKB_CB(skb)->seq, end) ||
		    before(TCP_SKB_CB(skb)->end_seq, start)) {
            /* 在发现gap后，就停止查找，将现有[start, end]范围内的数据进行合并 */
			tcp_collapse(sk, &tp->out_of_order_queue,
				     head, skb, start, end);
			head = skb;
			if (!skb)
				break;
			/* Start new segment */
			start = TCP_SKB_CB(skb)->seq;
			end = TCP_SKB_CB(skb)->end_seq;
        /* 如果发现了连续的数据，则调整start或end */
		} else {
			if (before(TCP_SKB_CB(skb)->seq, start))
				start = TCP_SKB_CB(skb)->seq;
			if (after(TCP_SKB_CB(skb)->end_seq, end))
				end = TCP_SKB_CB(skb)->end_seq;
		}
	}
}

/*
 * Purge the out-of-order queue.
 * Return true if queue was pruned.
 */
/* 对OFO queue的prune效果：直接清空！  后果其实也是很严重的，但在内存怎么都不够用的情况，只好出此下策 */
static bool tcp_prune_ofo_queue(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	bool res = false;

    /* 如果OFO queue不为空，则将其清空 */
	if (!skb_queue_empty(&tp->out_of_order_queue)) {
        /* OFO queue的prune就是直接清空，该计数器计算的是OFO queue被清空的次数 */
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_OFOPRUNED);
		__skb_queue_purge(&tp->out_of_order_queue);

		/* Reset SACK state.  A conforming SACK implementation will
		 * do the same at a timeout based retransmit.  When a connection
		 * is in a sad state like this, we care only about integrity
		 * of the connection not performance.
		 */
        /* 将SACK信息清空 */
		if (tp->rx_opt.sack_ok)
			tcp_sack_reset(&tp->rx_opt);
        /* 清空OFO queue之后，更新sk_forward_alloc */
		sk_mem_reclaim(sk);
		res = true;
	}
	return res;
}

/* Reduce allocated memory if we can, trying to get
 * the socket within its memory limits again.
 *
 * Return less than zero if we should start dropping frames
 * until the socket owning process reads some of the data
 * to stabilize the situation.
 */
/* 尝试减少receive queue和out-of-order queue的内存开销 */
/* ADI注解：tcp_prune_queue() is called when socket has exhausted its quota of receive buffer.
 * The idea is that we can still try to generate some space out by collapsing queues.
 */
static int tcp_prune_queue(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	SOCK_DEBUG(sk, "prune_queue: c=%x\n", tp->copied_seq);

    /* 该计数器记录tcp_prune_queue()被调用的次数，即尝试减少receive queue和OFO queue内存开销的次数 */
    /* 由于压缩OFO queue和receive queue的过程都是非常耗时的操作，因此即使是单单的调用这个函数的次数也应该很少才正常 */
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_PRUNECALLED);

    /* 如果是接受缓存占用的内存开销超过上限sk_rcvbuf导致的prune，
     * 则尝试调大sk_rcvbuf，如果调不大，就要限制rcv_ssthresh到2MSS */
	if (atomic_read(&sk->sk_rmem_alloc) >= sk->sk_rcvbuf)
		tcp_clamp_window(sk);
    /* 如果是memory pressure状态导致的prune，则限制rcv_ssthresh到4MSS */
	else if (sk_under_memory_pressure(sk))
		tp->rcv_ssthresh = min(tp->rcv_ssthresh, 4U * tp->advmss);

    /* 首先合并OFO queue中的skb */
	tcp_collapse_ofo_queue(sk);
    /* 如果receive queue不为空，则也要合并 */
	if (!skb_queue_empty(&sk->sk_receive_queue))
		tcp_collapse(sk, &sk->sk_receive_queue,
			     skb_peek(&sk->sk_receive_queue),
			     NULL,
			     tp->copied_seq, tp->rcv_nxt);
    /* 压缩queue之后，可能能腾出一些mem，sk_rmem_alloc可能有机会缩小 */
	sk_mem_reclaim(sk);

    /* 如果合并成功后sk_rmem_alloc比sk_rcvbuf小了，则返回0，表示合并成功，mem开销已经没问题了, 
     * 可以继续往receive queue放数据了 */
	if (atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf)
		return 0;

	/* Collapsing did not help, destructive actions follow.
	 * This must not ever occur. */
    /* 以下的代码应该永远不要被触发 */

    /* 如果普通的合并操作还是没能腾出足够的空间出来，那么就需要对OFO queue进行丢弃 */
	tcp_prune_ofo_queue(sk);

    /* 如果清空OFO queue之后，sk_rmem_alloc没超过限制，依然返回0，表示可以继续往receive queue中放数据了 */
	if (atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf)
		return 0;

	/* If we are really being abused, tell the caller to silently
	 * drop receive data on the floor.  It will get retransmitted
	 * and hopefully then we'll have sufficient space.
	 */
    /* 如果清空了OFO queue后，mem还是不够，那么只好返回-1让sk默认的开始丢数据包了
     * rcvpruned计数器表示需要进入此种窘境的次数 */
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_RCVPRUNED);

	/* Massive buffer overcommit. */
    /* 将用于判断fast path的flag清空，使用slow path来处理接收到的数据包 */
	tp->pred_flags = 0;
	return -1;
}

/* RFC2861, slow part. Adjust cwnd, after it was not full during one rto.
 * As additional protections, we do not touch cwnd in retransmission phases,
 * and if application hit its sndbuf limit recently.
 */
/* slow start after idle的策略 */
void tcp_cwnd_application_limited(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Open &&
	    sk->sk_socket && !test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		/* Limited by application or receiver window. */
		u32 init_win = tcp_init_cwnd(tp, __sk_dst_get(sk));
		u32 win_used = max(tp->snd_cwnd_used, init_win);
		if (win_used < tp->snd_cwnd) {
            /* 设置ssthresh为当前cwnd的75% */
			tp->snd_ssthresh = tcp_current_ssthresh(sk);
            /* 降低cwnd */
			tp->snd_cwnd = (tp->snd_cwnd + win_used) >> 1;
		}
		tp->snd_cwnd_used = 0;
	}
	tp->snd_cwnd_stamp = tcp_time_stamp;
}

/* 判断是否应该增大sndbuf上限了 */
static bool tcp_should_expand_sndbuf(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	/* If the user specified a specific send buffer setting, do
	 * not modify it.
	 */
    /* 如果是用户指定的sndbuf大小，则不能调整 */
	if (sk->sk_userlocks & SOCK_SNDBUF_LOCK)
		return false;

	/* If we are under global TCP memory pressure, do not expand.  */
    /* 如果在memory pressure状态下，则不应该再增大sndbuf
     * note: 这就是memory pressure发挥作用的一个场景 */
	if (sk_under_memory_pressure(sk))
		return false;

	/* If we are under soft global TCP memory pressure, do not expand.  */
    /* 如果TCP全局使用的内存超过了tcp_mem[0]，则也不会扩展sndbuf */
	if (sk_memory_allocated(sk) >= sk_prot_mem_limits(sk, 0))
		return false;

	/* If we filled the congestion window, do not expand.  */
    /* 如果数据发送受限于cwnd, 则也不需要扩展sndbuf */
	if (tp->packets_out >= tp->snd_cwnd)
		return false;

	return true;
}

/* When incoming ACK allowed to free some skb from write_queue,
 * we remember this event in flag SOCK_QUEUE_SHRUNK and wake up socket
 * on the exit from tcp input handler.
 *
 * PROBLEM: sndbuf expansion does not work well with largesend.
 */
/* 当有数据被ACK掉了，则要调整sndbuf，同时也要唤醒BSD socket继续写数据到sndbuf */
static void tcp_new_space(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

    /* 如果需要增大sndbuf，则将sndbuf调整为cwnd的2倍 */
	if (tcp_should_expand_sndbuf(sk)) {
		int sndmem = SKB_TRUESIZE(max_t(u32,
						tp->rx_opt.mss_clamp,
						tp->mss_cache) +
					  MAX_TCP_HEADER);
		int demanded = max_t(unsigned int, tp->snd_cwnd,
				     tp->reordering + 1);
		sndmem *= 2 * demanded;
        /* sndbuf不能超过tcp_wmem[2] */
		if (sndmem > sk->sk_sndbuf)
			sk->sk_sndbuf = min(sndmem, sysctl_tcp_wmem[2]);
        /* TODO： 这个变量的作用要好好总结一下，这里只是调整了sndbuf，并没有调整cwnd，它也更新了 */
		tp->snd_cwnd_stamp = tcp_time_stamp;
	}

    /* TCP协议对应的处理函数：sk_stream_write_space() */
	sk->sk_write_space(sk);
}

/* 如果sndbuf最近有skb被释放掉，则会打上SOCK_QUEUE_SHRUNK标记
 * 此函数的作用就是判断是否有这个标记，如果有，则要及时通知sk有新内存被释放了
 * 比如就可以继续将数据从用户控件拷贝到sndbuf中了 */
static void tcp_check_space(struct sock *sk)
{
	if (sock_flag(sk, SOCK_QUEUE_SHRUNK)) {
		sock_reset_flag(sk, SOCK_QUEUE_SHRUNK);
        /* 如果有对应的BSD socket, 并且之前它被设置了SOCK_NOSPACE标记，则要唤醒他 */
		if (sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &sk->sk_socket->flags))
			tcp_new_space(sk);
	}
}

static inline void tcp_data_snd_check(struct sock *sk)
{
	tcp_push_pending_frames(sk);
	tcp_check_space(sk);
}

/*
 * Check if sending an ack is needed.
 */
/* 在收到对端的数据后，判断是否需要发送ACK 
 * 满足以下条件之一时，立即发送一个ACK
 *  a. 收到超过一个MSS的数据 并且 XXX
 *  b. 有需要快速被发送的ACK等待发送
 *  c. 有乱序发生时
 * 否则发送一个delayedack */
static void __tcp_ack_snd_check(struct sock *sk, int ofo_possible)
{
	struct tcp_sock *tp = tcp_sk(sk);

	    /* More than one full frame received... */
	if (((tp->rcv_nxt - tp->rcv_wup) > inet_csk(sk)->icsk_ack.rcv_mss &&
	     /* ... and right edge of window advances far enough.
	      * (tcp_recvmsg() will send ACK otherwise). Or...
	      */
	     __tcp_select_window(sk) >= tp->rcv_wnd) ||
	    /* We ACK each frame or... */
	    tcp_in_quickack_mode(sk) ||
	    /* We have out of order data. */
	    (ofo_possible && skb_peek(&tp->out_of_order_queue))) {
		/* Then ack it now */
		tcp_send_ack(sk);
	} else {
		/* Else, send delayed ack. */
		tcp_send_delayed_ack(sk);
	}
}

static inline void tcp_ack_snd_check(struct sock *sk)
{
	if (!inet_csk_ack_scheduled(sk)) {
		/* We sent a data segment already. */
		return;
	}
	__tcp_ack_snd_check(sk, 1);
}

/*
 *	This routine is only called when we have urgent data
 *	signaled. Its the 'slow' part of tcp_urg. It could be
 *	moved inline now as tcp_urg is only called from one
 *	place. We handle URGent data wrong. We have to - as
 *	BSD still doesn't use the correction from RFC961.
 *	For 1003.1g we should support a new option TCP_STDURG to permit
 *	either form (or just set the sysctl tcp_stdurg).
 */
/* 检查urgent data合法性，如果合法，则记录urgent data的序号tp->urg_seq中, 此时还没有存入tp->urg_data中 */
static void tcp_check_urg(struct sock *sk, const struct tcphdr *th)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 ptr = ntohs(th->urg_ptr);

    /* 关于urgent pointer有两种定义：
     *      Linux implementation supports both theories of urgent byte,
     *      where one says that an urgent byte is one byte ahead of the urgent pointer mark
     *      and the other one says that an urgent byte is exactly pointed to by an urgent pointer mark.
     * 所以sysctl_tcp_stdurg应该是在这两种定义中切换的作用
     */
	if (ptr && !sysctl_tcp_stdurg)
		ptr--;
    /* th->urg_ptr中存的是相对于th->seq的偏移 */
	ptr += ntohl(th->seq);

	/* Ignore urgent data that we've already seen and read. */
    /* 忽视已处理过的urgent data */
	if (after(tp->copied_seq, ptr))
		return;

	/* Do not replay urg ptr.
	 *
	 * NOTE: interesting situation not covered by specs.
	 * Misbehaving sender may send urg ptr, pointing to segment,
	 * which we already have in ofo queue. We are not able to fetch
	 * such data and will stay in TCP_URG_NOTYET until will be eaten
	 * by recvmsg(). Seems, we are not obliged to handle such wicked
	 * situations. But it is worth to think about possibility of some
	 * DoSes using some hypothetical application level deadlock.
	 */
    /* 如果ptr在rcv_nxt之前，也是不处理的 */
	if (before(ptr, tp->rcv_nxt))
		return;

	/* Do we already have a newer (or duplicate) urgent pointer? */
    /* tp->urg_data仅保留最新的urgent data */
	if (tp->urg_data && !after(ptr, tp->urg_seq))
		return;

	/* Tell the world about our new urgent pointer. */
    /* 发送信号 */
	sk_send_sigurg(sk);

	/* We may be adding urgent data when the last byte read was
	 * urgent. To do this requires some care. We cannot just ignore
	 * tp->copied_seq since we would read the last urgent byte again
	 * as data, nor can we alter copied_seq until this data arrives
	 * or we break the semantics of SIOCATMARK (and thus sockatmark())
	 *
	 * NOTE. Double Dutch. Rendering to plain English: author of comment
	 * above did something sort of 	send("A", MSG_OOB); send("B", MSG_OOB);
	 * and expect that both A and B disappear from stream. This is _wrong_.
	 * Though this happens in BSD with high probability, this is occasional.
	 * Any application relying on this is buggy. Note also, that fix "works"
	 * only in this artificial test. Insert some normal data between A and B and we will
	 * decline of BSD again. Verdict: it is better to remove to trap
	 * buggy users.
	 */
    /* 如果不是inline模式，则需要将copied_seq加1，才能接着处理正常的TCP数据 */
	if (tp->urg_seq == tp->copied_seq && tp->urg_data &&
	    !sock_flag(sk, SOCK_URGINLINE) && tp->copied_seq != tp->rcv_nxt) {
		struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);
		tp->copied_seq++;
		if (skb && !before(tp->copied_seq, TCP_SKB_CB(skb)->end_seq)) {
			__skb_unlink(skb, &sk->sk_receive_queue);
			__kfree_skb(skb);
		}
	}

    /* 设置URGENT data等待接收标记, 因为urg_seq对应的数据可能还没收到 */
	tp->urg_data = TCP_URG_NOTYET;
	tp->urg_seq = ptr;

	/* Disable header prediction. */
	tp->pred_flags = 0;
}

/* This is the 'fast' part of urgent handling. */
/* 处理收到的urgent data */
static void tcp_urg(struct sock *sk, struct sk_buff *skb, const struct tcphdr *th)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Check if we get a new urgent pointer - normally not. */
	if (th->urg)
		tcp_check_urg(sk, th);

	/* Do we wait for any urgent data? - normally not... */
	if (tp->urg_data == TCP_URG_NOTYET) {
		u32 ptr = tp->urg_seq - ntohl(th->seq) + (th->doff * 4) -
			  th->syn;

		/* Is the urgent pointer pointing into this packet? */
		if (ptr < skb->len) {
			u8 tmp;
			if (skb_copy_bits(skb, ptr, &tmp, 1))
				BUG();
            /* 保存urg_data */
			tp->urg_data = TCP_URG_VALID | tmp;
			if (!sock_flag(sk, SOCK_DEAD))
                /* 通告socket，收到的数据，需要处理了 */
				sk->sk_data_ready(sk, 0);
		}
	}
}

/* 将skb中的数据拷贝到用户态的iovec中 */
static int tcp_copy_to_iovec(struct sock *sk, struct sk_buff *skb, int hlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int chunk = skb->len - hlen;
	int err;

	local_bh_enable();
	if (skb_csum_unnecessary(skb))
		err = skb_copy_datagram_iovec(skb, hlen, tp->ucopy.iov, chunk);
	else
		err = skb_copy_and_csum_datagram_iovec(skb, hlen,
						       tp->ucopy.iov);

	if (!err) {
		tp->ucopy.len -= chunk;
		tp->copied_seq += chunk;
		tcp_rcv_space_adjust(sk);
	}

	local_bh_disable();
	return err;
}

static __sum16 __tcp_checksum_complete_user(struct sock *sk,
					    struct sk_buff *skb)
{
	__sum16 result;

	if (sock_owned_by_user(sk)) {
		local_bh_enable();
		result = __tcp_checksum_complete(skb);
		local_bh_disable();
	} else {
		result = __tcp_checksum_complete(skb);
	}
	return result;
}

static inline bool tcp_checksum_complete_user(struct sock *sk,
					     struct sk_buff *skb)
{
	return !skb_csum_unnecessary(skb) &&
	       __tcp_checksum_complete_user(sk, skb);
}

#ifdef CONFIG_NET_DMA
static bool tcp_dma_try_early_copy(struct sock *sk, struct sk_buff *skb,
				  int hlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int chunk = skb->len - hlen;
	int dma_cookie;
	bool copied_early = false;

	if (tp->ucopy.wakeup)
		return false;

	if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
		tp->ucopy.dma_chan = net_dma_find_channel();

	if (tp->ucopy.dma_chan && skb_csum_unnecessary(skb)) {

		dma_cookie = dma_skb_copy_datagram_iovec(tp->ucopy.dma_chan,
							 skb, hlen,
							 tp->ucopy.iov, chunk,
							 tp->ucopy.pinned_list);

		if (dma_cookie < 0)
			goto out;

		tp->ucopy.dma_cookie = dma_cookie;
		copied_early = true;

		tp->ucopy.len -= chunk;
		tp->copied_seq += chunk;
		tcp_rcv_space_adjust(sk);

		if ((tp->ucopy.len == 0) ||
		    (tcp_flag_word(tcp_hdr(skb)) & TCP_FLAG_PSH) ||
		    (atomic_read(&sk->sk_rmem_alloc) > (sk->sk_rcvbuf >> 1))) {
			tp->ucopy.wakeup = 1;
			sk->sk_data_ready(sk, 0);
		}
	} else if (chunk > 0) {
		tp->ucopy.wakeup = 1;
		sk->sk_data_ready(sk, 0);
	}
out:
	return copied_early;
}
#endif /* CONFIG_NET_DMA */

/* Does PAWS and seqno based validation of an incoming segment, flags will
 * play significant role here.
 */
/* 检查接收数据包的合法性, 包括PAWS、seqno、reset flag等 */
static bool tcp_validate_incoming(struct sock *sk, struct sk_buff *skb,
				  const struct tcphdr *th, int syn_inerr)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* RFC1323: H1. Apply PAWS check first. */
    /* 如果开启了timestamp选项，则进行基于timestamp的PAWS检查 */
	if (tcp_fast_parse_options(skb, th, tp) && tp->rx_opt.saw_tstamp &&
	    tcp_paws_discard(sk, skb)) {
		if (!th->rst) {
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_PAWSESTABREJECTED);
			tcp_send_dupack(sk, skb);
			goto discard;
		}
		/* Reset is accepted even if it did not pass PAWS. */
        /* TODO: 这样不会导致reset伪造成功的概率更高么 ? */
	}

	/* Step 1: check sequence number */
	if (!tcp_sequence(tp, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq)) {
		/* RFC793, page 37: "In all states except SYN-SENT, all reset
		 * (RST) segments are validated by checking their SEQ-fields."
		 * 从上面这句话也可以看出reset数据包的合法性检查真的是太简单了 !
		 * And page 69: "If an incoming segment is not acceptable,
		 * an acknowledgment should be sent in reply (unless the RST
		 * bit is set, if so drop the segment and return)".
		 */
        /* 见上面一段英文解释 */
		if (!th->rst) {
			if (th->syn)
				goto syn_challenge;
			tcp_send_dupack(sk, skb);
		}
		goto discard;
	}

	/* Step 2: check RST bit */
	if (th->rst) {
		/* RFC 5961 3.2 :
		 * If sequence number exactly matches RCV.NXT, then
		 *     RESET the connection
		 * else
		 *     Send a challenge ACK
		 */
		if (TCP_SKB_CB(skb)->seq == tp->rcv_nxt)
			tcp_reset(sk);
		else
            /* 如果reset包的序号不吻合，则发送一个ACK给对端。
             * 如果对端真的想reset这个数据包的话，会回复一个序号正确的reset
             * 如果对端没有再发送reset给本端，则一切能恢复正常。就像没收到过这个序号不对的reset包一样。 */
			tcp_send_challenge_ack(sk);
		goto discard;
	}

	/* step 3: check security and precedence [ignored] */

	/* step 4: Check for a SYN
	 * RFC 5691 4.2 : Send a challenge ack
	 */
	if (th->syn) {
    /* 遇到重传的SYN/ACK时，就会触发该机制 */
syn_challenge:
		if (syn_inerr)
			TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_INERRS);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPSYNCHALLENGE);
		tcp_send_challenge_ack(sk);
		goto discard;
	}

	return true;

discard:
	__kfree_skb(skb);
	return false;
}

/* fast path被选中,就意味着TCP流的所有的数据传输都是符合预期的。
 * 所谓符合预期，从整体上就可以理解为：
 *      数据包都是按序到达且没有丢包
 * 带着这个思路去理解下面的代码，就比较好懂一些。
 */
/*
 *	TCP receive function for the ESTABLISHED state.
 *
 *	It is split into a fast path and a slow path. The fast path is
 * 	disabled when:
 *	- A zero window was announced from us - zero window probing
 *        is only handled properly in the slow path.
 *	- Out of order segments arrived.
 *	- Urgent data is expected.
 *	- There is no buffer space left
 *	- Unexpected TCP flags/window values/header lengths are received
 *	  (detected by checking the TCP header against pred_flags)
 *	- Data is sent in both directions. Fast path only supports pure senders
 *	  or pure receivers (this means either the sequence number or the ack
 *	  value must stay constant)
 *	    -- TODO-DONE
 *	        疑问1：为什么要限制数据单向发送？
 *	            -- 这样有一方的ack seq就不会改变
 *	        疑问2：具体是如何做到限制数据单向发送的？是严格的完全单向，还是一段时间内是单向的？
 *	            -- either the sequence number or the ack value must stay constant
 *	- Unexpected TCP option.
 *
 *	When these conditions are not satisfied it drops into a standard
 *	receive procedure patterned after RFC793 to handle all cases.
 *	The first three cases are guaranteed by proper pred_flags setting,
 *	the rest is checked inline. Fast processing is turned on in
 *	tcp_data_queue when everything is OK.
 */
/* Linux中两种机制处理收到的TCP包： fast path 和 slow path
 *      a. fast path: 由于没有发生任何异常，一切都从简处理，加快处理速度
 *          1. 处理收到到的数据
 *          2. 发送ACK或新数据
 *          3. 存储timestamp
 *      b. slow path: 出现异常情况后，一切从严判断。异常情况包括：zero window、乱序、内存空间问题、意外的TCP选项
 * 在Linux中，选择哪一种机制是由一个四字节的prediction flag来快速判断的。
 */
int tcp_rcv_established(struct sock *sk, struct sk_buff *skb,
			const struct tcphdr *th, unsigned int len)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (unlikely(sk->sk_rx_dst == NULL))
		inet_csk(sk)->icsk_af_ops->sk_rx_dst_set(sk, skb);
	/*
	 *	Header prediction.
	 *	The code loosely follows the one in the famous
	 *	"30 instruction TCP receive" Van Jacobson mail.
	 *
	 *	Van's trick is to deposit buffers into socket queue
	 *	on a device interrupt, to call tcp_recv function
	 *	on the receive process context and checksum and copy
	 *	the buffer to user space. smart...
	 *
	 *	Our current scheme is not silly either but we take the
	 *	extra cost of the net_bh soft interrupt processing...
	 *	We do checksum and copy also but from device to kernel.
	 */

	tp->rx_opt.saw_tstamp = 0;

	/*	pred_flags is 0xS?10 << 16 + snd_wnd
	 *	if header_prediction is to be made
	 *	'S' will always be tp->tcp_header_len >> 2
	 *	'?' will be 0 for the fast path, otherwise pred_flags is 0 to
	 *  turn it off	(when there are holes in the receive
	 *	 space for instance)
	 *	PSH flag is ignored.
	 */
    /* TODO-DONE: pred_flag含义？ tcp_flag_word()含义？ */
    /* tcp_flag_word()是直接提取出TCP头部中的header len + reserved + flag + rwnd 这四个字节，
     * pred_flag是之前这四个字节的缓存 */ 
    /* 如果满足这个条件，说明没有异常发生，就直接可以处理该数据包了 */
	if ((tcp_flag_word(th) & TCP_HP_BITS) == tp->pred_flags &&
	    TCP_SKB_CB(skb)->seq == tp->rcv_nxt &&                  /* skb的序号刚好就是期望收到的序号 */
	    !after(TCP_SKB_CB(skb)->ack_seq, tp->snd_nxt)) {        /* skb的尾序号不超过snd_nxt，算是合法性检测 */
		int tcp_header_len = tp->tcp_header_len;

		/* Timestamp header prediction: tcp_header_len
		 * is automatically equal to th->doff*4 due to pred_flags
		 * match.
		 */

		/* Check timestamp */
        /* 如果刚好仅使用了timestamp选项, 因为在"TCP正常包传输"过程中，TCP包仅
         * 可能包括timestamp选项。SACK_PERMITTED，WIN_SACLE都只能在三次握手时使用 */
        /* 而在正常的数据传输过程中，只会有timestamp数据包 */
		if (tcp_header_len == sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) {
			/* No? Slow path! */
            /* 如果解析失败，则说明带了选项，又不是一个正常的timestamp选项。
             * 则可能出了问题，进而进入slow_path */
			if (!tcp_parse_aligned_timestamp(tp, th))
				goto slow_path;

			/* If PAWS failed, check it more carefully in slow path */
            /* 使用timestamp的PAWS机制，TODO: ts_recent具体是怎么设置的？, 内在含义是什么？ */
			if ((s32)(tp->rx_opt.rcv_tsval - tp->rx_opt.ts_recent) < 0)
				goto slow_path;

			/* DO NOT update ts_recent here, if checksum fails
			 * and timestamp was corrupted part, it will result
			 * in a hung connection since we will drop all
			 * future packets due to the PAWS test.
			 */
		}

		if (len <= tcp_header_len) {
			/* Bulk data transfer: sender */
            /* 如果收到的是一个不带数据的ACK包，则本地应该是一个数据发送方，对端是一个数据接收方 */
			if (len == tcp_header_len) {
				/* Predicted packet is in window by definition.
				 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
				 * Hence, check seq<=rcv_wup reduces to:
				 */
				if (tcp_header_len == (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&   /* 如果有且仅有timestamp */
                    /* 如果对端是一个数据接收方，那么rcv_nxt是不会变化的
                     * rcv_wup是上次本地发送变化过的rwnd到对端时，记录的rcv_nxt */
				    tp->rcv_nxt == tp->rcv_wup)     
                    /* 至此，已经判断出这个一个按序(序号和timestap)到达的纯ACK包，并且本地是数据发送方，对端是数据接收方 */
					tcp_store_ts_recent(tp);    /* 可以放心的更新ts_recent值了,至于为什么放心，看下面一条源码注释 */

				/* We know that such packets are checksummed
				 * on entry.
				 */
				tcp_ack(sk, skb, 0);    /* 调用tcp_ack()处理收到的ACK包，flag置为0 */
				__kfree_skb(skb);       /* 将收到的纯ACK对应的skb释放掉 */
				tcp_data_snd_check(sk); /* 将pending在sndbuf中的数据发送出去，如果有需要的话还会增大sndbuf的大小 */
				return 0;
			} else { /* Header too small */
                /* 如果实际的包大小，比tp->doff * 4计算的小，则是一个不正确的TCP包，丢弃并增加计数器 */
				TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_INERRS);
				goto discard;       /* discard的处理动作就是释放skb所占内存 */
			}
		} else {
            /* 进入此else，说明该ACK包还带有数据 */
			int eaten = 0;
			int copied_early = 0;
			bool fragstolen = false;

            /* 如果receive queue中的所有数据都已经被用户处理完了,
             * 并且，
             * SKB中的数据不超过用户请求的数据长度
             *   -- 第二个判断的目的：skb中的数据要么全部拷贝到user space, 要不就不要动它。否则拷贝一半留下一半非常麻烦 */
			if (tp->copied_seq == tp->rcv_nxt &&
			    len - tcp_header_len <= tp->ucopy.len) {
#ifdef CONFIG_NET_DMA
				if (tp->ucopy.task == current &&
				    sock_owned_by_user(sk) &&
				    tcp_dma_try_early_copy(sk, skb, tcp_header_len)) {
					copied_early = 1;
					eaten = 1;
				}
#endif
                /* 该函数可能从用户态recv()触发调用，也可能在SOFT IRQ模式下调用
                 * 要想将数据拷贝到user space，只能是用户调用recv()才会将数据拷贝到用户态的iovec */
				if (tp->ucopy.task == current &&
				    sock_owned_by_user(sk) && !copied_early) {
					__set_current_state(TASK_RUNNING);

                    /* 将skb中的数据拷贝到用户态的iovec中 */
					if (!tcp_copy_to_iovec(sk, skb, tcp_header_len))
                        /* eaten表示skb数据已经拷贝到用户态iovec了，不需要放到receive queue中了 */
						eaten = 1;
				}
				if (eaten) {
					/* Predicted packet is in window by definition.
					 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
					 * Hence, check seq<=rcv_wup reduces to:
					 */
					if (tcp_header_len == (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
					    tp->rcv_nxt == tp->rcv_wup)
						tcp_store_ts_recent(tp);

					tcp_rcv_rtt_measure_ts(sk, skb);

                    /* 去掉TCP 头部 */
					__skb_pull(skb, tcp_header_len);
					tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
                    /* 数据直接放到了user space的iovec, 计数器增加 */
					NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPHPHITSTOUSER);
				}
				if (copied_early)
					tcp_cleanup_rbuf(sk, skb->len);
			}
            /* 如果数据包没有被直接放到user space */
			if (!eaten) {
                /* 首先检查checksum */
				if (tcp_checksum_complete_user(sk, skb))
					goto csum_error;

                /* forward alloc内存不足，此时fast path需要特殊处理 */
				if ((int)skb->truesize > sk->sk_forward_alloc)
					goto step5;

				/* Predicted packet is in window by definition.
				 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
				 * Hence, check seq<=rcv_wup reduces to:
				 */
				if (tcp_header_len ==
				    (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
				    tp->rcv_nxt == tp->rcv_wup)
					tcp_store_ts_recent(tp);

				tcp_rcv_rtt_measure_ts(sk, skb);

                /* skb通过fast path形式，加入到了receive queue中
                 * 理论上HP计数器越多越好!!! */
				NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPHPHITS);

				/* Bulk data transfer: receiver */
                /* 此时返回的eaten表示skb是否与接收队列的尾skb合并成功 */
				eaten = tcp_queue_rcv(sk, skb, tcp_header_len,
						      &fragstolen);
			}

            /* TODO： 收到数据后，要进行的动作 */
			tcp_event_data_recv(sk, skb);

            /* 如果接收到的ack与snd_una不相等，则要调用tcp_ack进行处理
             * 场景: 上一个发送的skb带有数据(如client request内容), 之后开始收数据 */
			if (TCP_SKB_CB(skb)->ack_seq != tp->snd_una) {
				/* Well, only one small jumplet in fast path... */
				tcp_ack(sk, skb, FLAG_DATA);
				tcp_data_snd_check(sk);
                /* 如果在tcp_data_snd_check()中有数据发送出去，那么就不会有ack等待被schedule，可以直接跳到no_ack
                 * 如果没有发送数据，则要主动调用_tcp_ack_snd_check()来尝试发送ACK */
				if (!inet_csk_ack_scheduled(sk))
					goto no_ack;
			}

			if (!copied_early || tp->rcv_nxt != tp->rcv_wup)
				__tcp_ack_snd_check(sk, 0);
no_ack:
#ifdef CONFIG_NET_DMA
			if (copied_early)
				__skb_queue_tail(&sk->sk_async_wait_queue, skb);
			else
#endif
			if (eaten)
				kfree_skb_partial(skb, fragstolen);
            /* 触发data ready的回调函数, 如sock_def_readable() */
			sk->sk_data_ready(sk, 0);
			return 0;
		}
	}

slow_path:
    /* 进入慢速路径的处理流程 */
	if (len < (th->doff << 2) || tcp_checksum_complete_user(sk, skb))
		goto csum_error;

    /* established状态收到的包，必须有ack或rst */
	if (!th->ack && !th->rst)
		goto discard;

	/*
	 *	Standard slow path.
	 */
    /* 检查数据包合法性 */
	if (!tcp_validate_incoming(sk, skb, th, 1))
		return 0;

step5:
    /* 处理ack */
	if (tcp_ack(sk, skb, FLAG_SLOWPATH | FLAG_UPDATE_TS_RECENT) < 0)
		goto discard;

	tcp_rcv_rtt_measure_ts(sk, skb);

	/* Process urgent data. */
	tcp_urg(sk, skb, th);

	/* step 7: process the segment text */
	tcp_data_queue(sk, skb);

	tcp_data_snd_check(sk);
	tcp_ack_snd_check(sk);
	return 0;

csum_error:
	TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_CSUMERRORS);
	TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_INERRS);

discard:
	__kfree_skb(skb);
	return 0;
}
EXPORT_SYMBOL(tcp_rcv_established);

void tcp_finish_connect(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	tcp_set_state(sk, TCP_ESTABLISHED);

	if (skb != NULL) {
		icsk->icsk_af_ops->sk_rx_dst_set(sk, skb);
		security_inet_conn_established(sk, skb);
	}

	/* Make sure socket is routed, for correct metrics.  */
	icsk->icsk_af_ops->rebuild_header(sk);

	tcp_init_metrics(sk);

	tcp_init_congestion_control(sk);

	/* Prevent spurious tcp_cwnd_restart() on first data
	 * packet.
	 */
	tp->lsndtime = tcp_time_stamp;

	tcp_init_buffer_space(sk);

	if (sock_flag(sk, SOCK_KEEPOPEN))
		inet_csk_reset_keepalive_timer(sk, keepalive_time_when(tp));

	if (!tp->rx_opt.snd_wscale)
		__tcp_fast_path_on(tp, tp->snd_wnd);
	else
		tp->pred_flags = 0;

	if (!sock_flag(sk, SOCK_DEAD)) {
		sk->sk_state_change(sk);
		sk_wake_async(sk, SOCK_WAKE_IO, POLL_OUT);
	}
}

static bool tcp_rcv_fastopen_synack(struct sock *sk, struct sk_buff *synack,
				    struct tcp_fastopen_cookie *cookie)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *data = tp->syn_data ? tcp_write_queue_head(sk) : NULL;
	u16 mss = tp->rx_opt.mss_clamp;
	bool syn_drop;

	if (mss == tp->rx_opt.user_mss) {
		struct tcp_options_received opt;

		/* Get original SYNACK MSS value if user MSS sets mss_clamp */
		tcp_clear_options(&opt);
		opt.user_mss = opt.mss_clamp = 0;
		tcp_parse_options(synack, &opt, 0, NULL);
		mss = opt.mss_clamp;
	}

	if (!tp->syn_fastopen)  /* Ignore an unsolicited cookie */
		cookie->len = -1;

	/* The SYN-ACK neither has cookie nor acknowledges the data. Presumably
	 * the remote receives only the retransmitted (regular) SYNs: either
	 * the original SYN-data or the corresponding SYN-ACK is lost.
	 */
	syn_drop = (cookie->len <= 0 && data && tp->total_retrans);

	tcp_fastopen_cache_set(sk, mss, cookie, syn_drop);

	if (data) { /* Retransmit unacked data in SYN */
		tcp_for_write_queue_from(data, sk) {
			if (data == tcp_send_head(sk) ||
			    __tcp_retransmit_skb(sk, data))
				break;
		}
		tcp_rearm_rto(sk);
		return true;
	}
	tp->syn_data_acked = tp->syn_data;
	return false;
}

static int tcp_rcv_synsent_state_process(struct sock *sk, struct sk_buff *skb,
					 const struct tcphdr *th, unsigned int len)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_fastopen_cookie foc = { .len = -1 };
	int saved_clamp = tp->rx_opt.mss_clamp;

	tcp_parse_options(skb, &tp->rx_opt, 0, &foc);
	if (tp->rx_opt.saw_tstamp)
		tp->rx_opt.rcv_tsecr -= tp->tsoffset;

	if (th->ack) {
		/* rfc793:
		 * "If the state is SYN-SENT then
		 *    first check the ACK bit
		 *      If the ACK bit is set
		 *	  If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send
		 *        a reset (unless the RST bit is set, if so drop
		 *        the segment and return)"
		 */
		if (!after(TCP_SKB_CB(skb)->ack_seq, tp->snd_una) ||
		    after(TCP_SKB_CB(skb)->ack_seq, tp->snd_nxt))
			goto reset_and_undo;

		if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr &&
		    !between(tp->rx_opt.rcv_tsecr, tp->retrans_stamp,
			     tcp_time_stamp)) {
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_PAWSACTIVEREJECTED);
			goto reset_and_undo;
		}

		/* Now ACK is acceptable.
		 *
		 * "If the RST bit is set
		 *    If the ACK was acceptable then signal the user "error:
		 *    connection reset", drop the segment, enter CLOSED state,
		 *    delete TCB, and return."
		 */

		if (th->rst) {
			tcp_reset(sk);
			goto discard;
		}

		/* rfc793:
		 *   "fifth, if neither of the SYN or RST bits is set then
		 *    drop the segment and return."
		 *
		 *    See note below!
		 *                                        --ANK(990513)
		 */
		if (!th->syn)
			goto discard_and_undo;

		/* rfc793:
		 *   "If the SYN bit is on ...
		 *    are acceptable then ...
		 *    (our SYN has been ACKed), change the connection
		 *    state to ESTABLISHED..."
		 */

		TCP_ECN_rcv_synack(tp, th);

		tcp_init_wl(tp, TCP_SKB_CB(skb)->seq);
		tcp_ack(sk, skb, FLAG_SLOWPATH);

		/* Ok.. it's good. Set up sequence numbers and
		 * move to established.
		 */
		tp->rcv_nxt = TCP_SKB_CB(skb)->seq + 1;
		tp->rcv_wup = TCP_SKB_CB(skb)->seq + 1;

		/* RFC1323: The window in SYN & SYN/ACK segments is
		 * never scaled.
		 */
		tp->snd_wnd = ntohs(th->window);

		if (!tp->rx_opt.wscale_ok) {
			tp->rx_opt.snd_wscale = tp->rx_opt.rcv_wscale = 0;
			tp->window_clamp = min(tp->window_clamp, 65535U);
		}

		if (tp->rx_opt.saw_tstamp) {
			tp->rx_opt.tstamp_ok	   = 1;
			tp->tcp_header_len =
				sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
			tp->advmss	    -= TCPOLEN_TSTAMP_ALIGNED;
			tcp_store_ts_recent(tp);
		} else {
			tp->tcp_header_len = sizeof(struct tcphdr);
		}

		if (tcp_is_sack(tp) && sysctl_tcp_fack)
			tcp_enable_fack(tp);

		tcp_mtup_init(sk);
		tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		tcp_initialize_rcv_mss(sk);

		/* Remember, tcp_poll() does not lock socket!
		 * Change state from SYN-SENT only after copied_seq
		 * is initialized. */
		tp->copied_seq = tp->rcv_nxt;

		smp_mb();

		tcp_finish_connect(sk, skb);

		if ((tp->syn_fastopen || tp->syn_data) &&
		    tcp_rcv_fastopen_synack(sk, skb, &foc))
			return -1;

		if (sk->sk_write_pending ||
		    icsk->icsk_accept_queue.rskq_defer_accept ||
		    icsk->icsk_ack.pingpong) {
			/* Save one ACK. Data will be ready after
			 * several ticks, if write_pending is set.
			 *
			 * It may be deleted, but with this feature tcpdumps
			 * look so _wonderfully_ clever, that I was not able
			 * to stand against the temptation 8)     --ANK
			 */
			inet_csk_schedule_ack(sk);
			icsk->icsk_ack.lrcvtime = tcp_time_stamp;
			tcp_enter_quickack_mode(sk);
			inet_csk_reset_xmit_timer(sk, ICSK_TIME_DACK,
						  TCP_DELACK_MAX, TCP_RTO_MAX);

discard:
			__kfree_skb(skb);
			return 0;
		} else {
			tcp_send_ack(sk);
		}
		return -1;
	}

	/* No ACK in the segment */

	if (th->rst) {
		/* rfc793:
		 * "If the RST bit is set
		 *
		 *      Otherwise (no ACK) drop the segment and return."
		 */

		goto discard_and_undo;
	}

	/* PAWS check. */
	if (tp->rx_opt.ts_recent_stamp && tp->rx_opt.saw_tstamp &&
	    tcp_paws_reject(&tp->rx_opt, 0))
		goto discard_and_undo;

	if (th->syn) {
		/* We see SYN without ACK. It is attempt of
		 * simultaneous connect with crossed SYNs.
		 * Particularly, it can be connect to self.
		 */
		tcp_set_state(sk, TCP_SYN_RECV);

		if (tp->rx_opt.saw_tstamp) {
			tp->rx_opt.tstamp_ok = 1;
			tcp_store_ts_recent(tp);
			tp->tcp_header_len =
				sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
		} else {
			tp->tcp_header_len = sizeof(struct tcphdr);
		}

		tp->rcv_nxt = TCP_SKB_CB(skb)->seq + 1;
		tp->rcv_wup = TCP_SKB_CB(skb)->seq + 1;

		/* RFC1323: The window in SYN & SYN/ACK segments is
		 * never scaled.
		 */
		tp->snd_wnd    = ntohs(th->window);
		tp->snd_wl1    = TCP_SKB_CB(skb)->seq;
		tp->max_window = tp->snd_wnd;

		TCP_ECN_rcv_syn(tp, th);

		tcp_mtup_init(sk);
		tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		tcp_initialize_rcv_mss(sk);

		tcp_send_synack(sk);
#if 0
		/* Note, we could accept data and URG from this segment.
		 * There are no obstacles to make this (except that we must
		 * either change tcp_recvmsg() to prevent it from returning data
		 * before 3WHS completes per RFC793, or employ TCP Fast Open).
		 *
		 * However, if we ignore data in ACKless segments sometimes,
		 * we have no reasons to accept it sometimes.
		 * Also, seems the code doing it in step6 of tcp_rcv_state_process
		 * is not flawless. So, discard packet for sanity.
		 * Uncomment this return to process the data.
		 */
		return -1;
#else
		goto discard;
#endif
	}
	/* "fifth, if neither of the SYN or RST bits is set then
	 * drop the segment and return."
	 */

discard_and_undo:
	tcp_clear_options(&tp->rx_opt);
	tp->rx_opt.mss_clamp = saved_clamp;
	goto discard;

reset_and_undo:
	tcp_clear_options(&tp->rx_opt);
	tp->rx_opt.mss_clamp = saved_clamp;
	return 1;
}

/*
 *	This function implements the receiving procedure of RFC 793 for
 *	all states except ESTABLISHED and TIME_WAIT.
 *	It's called from both tcp_v4_rcv and tcp_v6_rcv and should be
 *	address independent.
 */
/* 返回大于零的数，表示要发送reset */
int tcp_rcv_state_process(struct sock *sk, struct sk_buff *skb,
			  const struct tcphdr *th, unsigned int len)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct request_sock *req;
	int queued = 0;

	tp->rx_opt.saw_tstamp = 0;

	switch (sk->sk_state) {
	case TCP_CLOSE:     /* 如果已经处于CLOSE状态，只好丢弃收到的包 */
		goto discard;

	case TCP_LISTEN:
        /* 如果处于LISTEN状态的socket，收到一个ACK，则返回1，让sk去回复一个reset包给对端
         * 注意：如果是合法的ACK，比如3WHS的最后一个ACK包，应该已经在tcp_v4_hnd_req()中处理好了
         *       传递到这里来的数据包应该只有SYN包才合法 */
		if (th->ack)    
			return 1;

        /* 处于LISTEN状态的socket，应该忽视对端发过来的reset包 */
		if (th->rst)
			goto discard;

		if (th->syn) {
            /* 如果SYN包里面，又带有FIN标记，则肯定是个非法的数据包，直接丢弃 */
			if (th->fin)
				goto discard;

            /* 调用tcp_v4_conn_request()来处理三次握手的第一个数据包
             * 有意思的是tcp_v4_conn_request()只会返回0，不需要发送reset给对端
             * 返回0，进入下面的kfree_skb(skb)步骤，所以tcp_v4_conn_request也并不需要负责释放skb */
			if (icsk->icsk_af_ops->conn_request(sk, skb) < 0)
				return 1;

			/* Now we have several options: In theory there is
			 * nothing else in the frame. KA9Q has an option to
			 * send data with the syn, BSD accepts data with the
			 * syn up to the [to be] advertised window and
			 * Solaris 2.1 gives you a protocol error. For now
			 * we just ignore it, that fits the spec precisely
			 * and avoids incompatibilities. It would be nice in
			 * future to drop through and process the data.
			 *
			 * Now that TTCP is starting to be used we ought to
			 * queue this data.
			 * But, this leaves one open to an easy denial of
			 * service attack, and SYN cookies can't defend
			 * against this problem. So, we drop the data
			 * in the interest of security over speed unless
			 * it's still in use.
			 */
            /* 注释解释的挺清楚的，目前Linux不会处理SYN包中携带的数据 */
			kfree_skb(skb);
			return 0;   /* 返回0表示正常结束 */
		}
        /* 如果不带SYN标记，则是一个非法的数据包，直接丢弃掉 */
		goto discard;

	case TCP_SYN_SENT:
		queued = tcp_rcv_synsent_state_process(sk, skb, th, len);
		if (queued >= 0)
			return queued;

		/* Do step6 onward by hand. */
		tcp_urg(sk, skb, th);
		__kfree_skb(skb);
		tcp_data_snd_check(sk);
		return 0;
	}

	req = tp->fastopen_rsk;
	if (req != NULL) {
		WARN_ON_ONCE(sk->sk_state != TCP_SYN_RECV &&
		    sk->sk_state != TCP_FIN_WAIT1);

		if (tcp_check_req(sk, skb, req, NULL, true) == NULL)
			goto discard;
	}

	if (!th->ack && !th->rst)
		goto discard;

	if (!tcp_validate_incoming(sk, skb, th, 0))
		return 0;

	/* step 5: check the ACK field */
	if (true) {
		int acceptable = tcp_ack(sk, skb, FLAG_SLOWPATH |
						  FLAG_UPDATE_TS_RECENT) > 0;

		switch (sk->sk_state) {
		case TCP_SYN_RECV:
			if (acceptable) {
				/* Once we leave TCP_SYN_RECV, we no longer
				 * need req so release it.
				 */
				if (req) {
					tcp_synack_rtt_meas(sk, req);
					tp->total_retrans = req->num_retrans;

					reqsk_fastopen_remove(sk, req, false);
				} else {
					/* Make sure socket is routed, for
					 * correct metrics.
					 */
					icsk->icsk_af_ops->rebuild_header(sk);
					tcp_init_congestion_control(sk);

					tcp_mtup_init(sk);
					tcp_init_buffer_space(sk);
					tp->copied_seq = tp->rcv_nxt;
				}
				smp_mb();
				tcp_set_state(sk, TCP_ESTABLISHED);
				sk->sk_state_change(sk);

				/* Note, that this wakeup is only for marginal
				 * crossed SYN case. Passively open sockets
				 * are not waked up, because sk->sk_sleep ==
				 * NULL and sk->sk_socket == NULL.
				 */
				if (sk->sk_socket)
					sk_wake_async(sk,
						      SOCK_WAKE_IO, POLL_OUT);

				tp->snd_una = TCP_SKB_CB(skb)->ack_seq;
				tp->snd_wnd = ntohs(th->window) <<
					      tp->rx_opt.snd_wscale;
				tcp_init_wl(tp, TCP_SKB_CB(skb)->seq);

				if (tp->rx_opt.tstamp_ok)
					tp->advmss -= TCPOLEN_TSTAMP_ALIGNED;

				if (req) {
					/* Re-arm the timer because data may
					 * have been sent out. This is similar
					 * to the regular data transmission case
					 * when new data has just been ack'ed.
					 *
					 * (TFO) - we could try to be more
					 * aggressive and retranmitting any data
					 * sooner based on when they were sent
					 * out.
					 */
					tcp_rearm_rto(sk);
				} else
					tcp_init_metrics(sk);

				/* Prevent spurious tcp_cwnd_restart() on
				 * first data packet.
				 */
				tp->lsndtime = tcp_time_stamp;

				tcp_initialize_rcv_mss(sk);
				tcp_fast_path_on(tp);
			} else {
				return 1;
			}
			break;

		case TCP_FIN_WAIT1:
			/* If we enter the TCP_FIN_WAIT1 state and we are a
			 * Fast Open socket and this is the first acceptable
			 * ACK we have received, this would have acknowledged
			 * our SYNACK so stop the SYNACK timer.
			 */
			if (req != NULL) {
				/* Return RST if ack_seq is invalid.
				 * Note that RFC793 only says to generate a
				 * DUPACK for it but for TCP Fast Open it seems
				 * better to treat this case like TCP_SYN_RECV
				 * above.
				 */
				if (!acceptable)
					return 1;
				/* We no longer need the request sock. */
				reqsk_fastopen_remove(sk, req, false);
				tcp_rearm_rto(sk);
			}
			if (tp->snd_una == tp->write_seq) {
				struct dst_entry *dst;

				tcp_set_state(sk, TCP_FIN_WAIT2);
				sk->sk_shutdown |= SEND_SHUTDOWN;

				dst = __sk_dst_get(sk);
				if (dst)
					dst_confirm(dst);

				if (!sock_flag(sk, SOCK_DEAD))
					/* Wake up lingering close() */
					sk->sk_state_change(sk);
				else {
					int tmo;

					if (tp->linger2 < 0 ||
					    (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
					     after(TCP_SKB_CB(skb)->end_seq - th->fin, tp->rcv_nxt))) {
						tcp_done(sk);
						NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONDATA);
						return 1;
					}

					tmo = tcp_fin_time(sk);
					if (tmo > TCP_TIMEWAIT_LEN) {
						inet_csk_reset_keepalive_timer(sk, tmo - TCP_TIMEWAIT_LEN);
					} else if (th->fin || sock_owned_by_user(sk)) {
						/* Bad case. We could lose such FIN otherwise.
						 * It is not a big problem, but it looks confusing
						 * and not so rare event. We still can lose it now,
						 * if it spins in bh_lock_sock(), but it is really
						 * marginal case.
						 */
						inet_csk_reset_keepalive_timer(sk, tmo);
					} else {
						tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
						goto discard;
					}
				}
			}
			break;

		case TCP_CLOSING:
			if (tp->snd_una == tp->write_seq) {
				tcp_time_wait(sk, TCP_TIME_WAIT, 0);
				goto discard;
			}
			break;

		case TCP_LAST_ACK:
			if (tp->snd_una == tp->write_seq) {
				tcp_update_metrics(sk);
				tcp_done(sk);
				goto discard;
			}
			break;
		}
	}

	/* step 6: check the URG bit */
	tcp_urg(sk, skb, th);

	/* step 7: process the segment text */
	switch (sk->sk_state) {
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
		if (!before(TCP_SKB_CB(skb)->seq, tp->rcv_nxt))
			break;
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
		/* RFC 793 says to queue data in these states,
		 * RFC 1122 says we MUST send a reset.
		 * BSD 4.4 also does reset.
		 */
		if (sk->sk_shutdown & RCV_SHUTDOWN) {
			if (TCP_SKB_CB(skb)->end_seq != TCP_SKB_CB(skb)->seq &&
			    after(TCP_SKB_CB(skb)->end_seq - th->fin, tp->rcv_nxt)) {
				NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONDATA);
				tcp_reset(sk);
				return 1;
			}
		}
		/* Fall through */
	case TCP_ESTABLISHED:
		tcp_data_queue(sk, skb);
		queued = 1;
		break;
	}

	/* tcp_data could move socket to TIME-WAIT */
	if (sk->sk_state != TCP_CLOSE) {
		tcp_data_snd_check(sk);
		tcp_ack_snd_check(sk);
	}

	if (!queued) {
discard:
		__kfree_skb(skb);
	}
	return 0;
}
EXPORT_SYMBOL(tcp_rcv_state_process);
