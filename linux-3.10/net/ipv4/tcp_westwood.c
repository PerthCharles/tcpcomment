/*
 * TCP Westwood+: end-to-end bandwidth estimation for TCP
 *
 *      Angelo Dell'Aera: author of the first version of TCP Westwood+ in Linux 2.4
 *
 * Support at http://c3lab.poliba.it/index.php/Westwood
 * Main references in literature:
 *
 * - Mascolo S, Casetti, M. Gerla et al.
 *   "TCP Westwood: bandwidth estimation for TCP" Proc. ACM Mobicom 2001
 *
 * - A. Grieco, s. Mascolo
 *   "Performance evaluation of New Reno, Vegas, Westwood+ TCP" ACM Computer
 *     Comm. Review, 2004
 *
 * - A. Dell'Aera, L. Grieco, S. Mascolo.
 *   "Linux 2.4 Implementation of Westwood+ TCP with Rate-Halving :
 *    A Performance Evaluation Over the Internet" (ICC 2004), Paris, June 2004
 *
 * Westwood+ employs end-to-end bandwidth measurement to set cwnd and
 * ssthresh after packet loss. The probing phase is as the original Reno.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>
#include <net/tcp.h>

/* TCP Westwood structure */
struct westwood {
    /* 计算bw_est的一个中间值，用于平滑采样 */
	u32    bw_ns_est;        /* first bandwidth estimation..not too smoothed 8) */
    /* 根据经过平滑过一次的bw_ns_est值，再计算最终的bw_est */
	u32    bw_est;           /* bandwidth estimate */
    /* 采样周期的起点 */
	u32    rtt_win_sx;       /* here starts a new evaluation... */
    /* 在测量时间内确认的字节数 */
	u32    bk;
    /* 记录处理完某一个数据包之前的snd_una，用于计算bk */
	u32    snd_una;          /* used for evaluating the number of acked bytes */
    /* 慢速路径下，被一个ACK包确认的字节数 */
	u32    cumul_ack;
    /* 当前被接收端乱序接收到的字节数 */
	u32    accounted;
    /* 每收到一个ACK，获取的一个rtt sample */
	u32    rtt;
	u32    rtt_min;          /* minimum observed RTT */
	u8     first_ack;        /* flag which infers that this is the first ack */
	u8     reset_rtt_min;    /* Reset RTT min to next RTT sample*/
};


/* TCP Westwood functions and constants */
#define TCP_WESTWOOD_RTT_MIN   (HZ/20)	/* 50ms */      /* 带宽至少50ms更新一次 */
#define TCP_WESTWOOD_INIT_RTT  (20*HZ)	/* maybe too conservative?! */

/*
 * @tcp_westwood_create
 * This function initializes fields used in TCP Westwood+,
 * it is called after the initial SYN, so the sequence numbers
 * are correct but new passive connections we have no
 * information about RTTmin at this time so we simply set it to
 * TCP_WESTWOOD_INIT_RTT. This value was chosen to be too conservative
 * since in this way we're sure it will be updated in a consistent
 * way as soon as possible. It will reasonably happen within the first
 * RTT period of the connection lifetime.
 */
/* westwood初始化函数，在TCP流初始化拥塞控制算法时调用 */
static void tcp_westwood_init(struct sock *sk)
{
	struct westwood *w = inet_csk_ca(sk);

	w->bk = 0;
	w->bw_ns_est = 0;
	w->bw_est = 0;
	w->accounted = 0;
	w->cumul_ack = 0;
	w->reset_rtt_min = 1;
	w->rtt_min = w->rtt = TCP_WESTWOOD_INIT_RTT;    /* 在未获得RTT sample前，默认使用20s作为RTT，真是太保守了 */
	w->rtt_win_sx = tcp_time_stamp;
	w->snd_una = tcp_sk(sk)->snd_una;
	w->first_ack = 1;
}

/*
 * @westwood_do_filter
 * Low-pass filter. Implemented using constant coefficients.
 */
/* ret_val = 7/8 * a + 1/8 * b，对采样进行平滑处理的公式
 * 调用时基本都是返回给a，即ret_val就是a */
static inline u32 westwood_do_filter(u32 a, u32 b)
{
	return ((7 * a) + b) >> 3;
}

/* 计算带宽估计值，delta表示时间周期长度，w->bk表示这个周期内被确认的字节数 */
static void westwood_filter(struct westwood *w, u32 delta)
{
	/* If the filter is empty fill it with the first sample of bandwidth  */
    /* 第一次采样时，也就没有平滑的必要的 */
	if (w->bw_ns_est == 0 && w->bw_est == 0) {
		w->bw_ns_est = w->bk / delta;
		w->bw_est = w->bw_ns_est;
	} else {
        /* 调用westwood_do_filter()对 "w->bk / delta"计算的带宽值进行平滑处理 */
		w->bw_ns_est = westwood_do_filter(w->bw_ns_est, w->bk / delta);
		w->bw_est = westwood_do_filter(w->bw_est, w->bw_ns_est);
	}
}

/*
 * @westwood_pkts_acked
 * Called after processing group of packets.
 * but all westwood needs is the last sample of srtt.
 */
/* westwood仅使用单一的rtt sample
 * 函数功能：获得一个有效的rtt 采样时，更新rtt值 */
static void tcp_westwood_pkts_acked(struct sock *sk, u32 cnt, s32 rtt)
{
	struct westwood *w = inet_csk_ca(sk);

	if (rtt > 0)
		w->rtt = usecs_to_jiffies(rtt);
}

/*
 * @westwood_update_window
 * It updates RTT evaluation window if it is the right moment to do
 * it. If so it calls filter for evaluating bandwidth.
 */
/* 每经过max(w->rtt, 50ms)长的时间，更新一次带宽估计
 * 点评：
 *      1. w->rtt的更新是直接使用的rtt采样，并没有进行过平滑，这点比较不合理
 *      2. 最小的更新周期为50ms，是否太长了点?
 *      3. westwood没有对rtt平滑，而是对计算的带宽估计值进行平滑，是否有点本末倒置 */
static void westwood_update_window(struct sock *sk)
{
	struct westwood *w = inet_csk_ca(sk);
    /* 计算距离采样周期开始时间的间隔 */
	s32 delta = tcp_time_stamp - w->rtt_win_sx;

	/* Initialize w->snd_una with the first acked sequence number in order
	 * to fix mismatch between tp->snd_una and w->snd_una for the first
	 * bandwidth sample
	 */
    /* first_ack的作用其实也就是保证刚开始采样时，snd_una的准确性 */
	if (w->first_ack) {
		w->snd_una = tcp_sk(sk)->snd_una;
		w->first_ack = 0;
	}

	/*
	 * See if a RTT-window has passed.
	 * Be careful since if RTT is less than
	 * 50ms we don't filter but we continue 'building the sample'.
	 * This minimum limit was chosen since an estimation on small
	 * time intervals is better to avoid...
	 * Obviously on a LAN we reasonably will always have
	 * right_bound = left_bound + WESTWOOD_RTT_MIN
	 */
	if (w->rtt && delta > max_t(u32, w->rtt, TCP_WESTWOOD_RTT_MIN)) {
        /* 如果采样时间已经超过max(w->rtt, 50ms)，则更新带宽估计值 */
		westwood_filter(w, delta);

        /* 开始下一个采样周期 */
		w->bk = 0;
		w->rtt_win_sx = tcp_time_stamp;
	}
}

/* 更新rtt_min */
static inline void update_rtt_min(struct westwood *w)
{
    /* 在进入Loss时，会设置重设rtt_min标记。
     * 内含：进入Loss意味着发生重大的链路问题，有可能路由选路也改变了，因此需要更新rtt_min */
	if (w->reset_rtt_min) {
		w->rtt_min = w->rtt;
		w->reset_rtt_min = 0;
	} else
		w->rtt_min = min(w->rtt, w->rtt_min);
}


/*
 * @westwood_fast_bw
 * It is called when we are in fast path. In particular it is called when
 * header prediction is successful. In such case in fact update is
 * straight forward and doesn't need any particular care.
 */
/* 快速路径时，更新带宽估计、bk(被确认的字节数)、rtt_min */
static inline void westwood_fast_bw(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct westwood *w = inet_csk_ca(sk);

	westwood_update_window(sk);

    /* 快速路径，说明处于Open状态，直接使用新的snd_una减去上次的值，就能得到被确认的数据量 */
	w->bk += tp->snd_una - w->snd_una;
	w->snd_una = tp->snd_una;
	update_rtt_min(w);
}

/*
 * @westwood_acked_count
 * This function evaluates cumul_ack for evaluating bk in case of
 * delayed or partial acks.
 */
/* 慢速路径时，更新被此ACK确认的字节数 
 * 感觉这个计算的太不严谨了，挂不得westwood在对重传阶段的带宽估计不准确 */
static inline u32 westwood_acked_count(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct westwood *w = inet_csk_ca(sk);

    /* 计算此ACK确认的字节数，第一步计算被按序确认的字节数
     * 1. delayed ack，或者前面有被丢失的ack时，此值是有可能非零的
     * 2. 如果是dupack，此时为零 */
	w->cumul_ack = tp->snd_una - w->snd_una;

	/* If cumul_ack is 0 this is a dupack since it's not moving
	 * tp->snd_una.
	 */
	if (!w->cumul_ack) {
        /* 记录接收端乱序收到的字节数，如果是一个dupack，则增加一个MSS值 */
		w->accounted += tp->mss_cache;
        /* 一个dupack也意味着对端收到了一个数据包，尽管是乱序的
         * 此时将被该ACK确认的字节数设置为一个mss */
		w->cumul_ack = tp->mss_cache;       
	}

    /* 如果cumul_ack大于mss_cache，则意味着不是一个dupack */
	if (w->cumul_ack > tp->mss_cache) {
		/* Partial or delayed ack */
        /* 如果是一个partial ack(累计确认的字节数还没有超过对端乱序接收的字节数)，
         * 那么更新对端依然处于乱序状态的字节数(accounted - cumul_ack)，
         * 同时假设：这个partial ack仅确认了一个数据包，其他包都已经被dupack确认过
         * 点评：westwood一直被诟病在重传阶段计算被确认的字节数不准确，我想这个地方就是一个原因
         * 一个partial ack并不一定仅确认了一个数据包 */
		if (w->accounted >= w->cumul_ack) {
			w->accounted -= w->cumul_ack;
			w->cumul_ack = tp->mss_cache;
		} else {
        /* 如果是一个delayed ack(对应情况应该是cumul_ack==2mss, accounted=0),
         * 或者是结束recovery时的那个ack(对应：cumul_ack应该覆盖所有接收端乱序收到的数据)
         * 点评：cumul_ack超过accounted也不一定意味着结束了recovery啊，所以感觉还是不够准确 */
			w->cumul_ack -= w->accounted;   /* 减掉已经被dupack所确认的字节数 */
			w->accounted = 0;
		}
	}

	w->snd_una = tp->snd_una;   /* 更新snd_una */

	return w->cumul_ack;
}


/*
 * TCP Westwood
 * Here limit is evaluated as Bw estimation*RTTmin (for obtaining it
 * in packets we use mss_cache). Rttmin is guaranteed to be >= 2
 * so avoids ever returning 0.
 */
/* 根据估计的带宽，和rtt_min来设置拥塞窗口和慢启动阈值
 * rtt_min相当于是链路没有排队时的时延，bw_est相当于是当前流可以占用的带宽 */
static u32 tcp_westwood_bw_rttmin(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct westwood *w = inet_csk_ca(sk);
	return max_t(u32, (w->bw_est * w->rtt_min) / tp->mss_cache, 2);
}

/* westwood算法的入口函数 */
static void tcp_westwood_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct westwood *w = inet_csk_ca(sk);

	switch (event) {
	case CA_EVENT_FAST_ACK:
        /* 处于快速路径，更新带宽估计 */
		westwood_fast_bw(sk);
		break;

    /* 在退出快速重传时，根据带宽估计，重新设置cwnd和ssthresh。
     * 所谓重新设置，就是会覆盖快速重传/快速恢复算法调整的cwnd值 */
	case CA_EVENT_COMPLETE_CWR:
		tp->snd_cwnd = tp->snd_ssthresh = tcp_westwood_bw_rttmin(sk);
		break;

    /* 在经历RTO超时时，cwnd会被设置为1，慢启动阈值会根据带宽估计更新 */
	case CA_EVENT_LOSS:
		tp->snd_ssthresh = tcp_westwood_bw_rttmin(sk);
		/* Update RTT_min when next ack arrives */
		w->reset_rtt_min = 1;
		break;

	case CA_EVENT_SLOW_ACK:
        /* 慢速路径时，更新带宽估计和被该ACK确认的字节数 */
		westwood_update_window(sk);
		w->bk += westwood_acked_count(sk);
		update_rtt_min(w);
		break;

	default:
		/* don't care */
		break;
	}
}


/* Extract info for Tcp socket info provided via netlink. */
static void tcp_westwood_info(struct sock *sk, u32 ext,
			      struct sk_buff *skb)
{
	const struct westwood *ca = inet_csk_ca(sk);
	if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcpvegas_info info = {
			.tcpv_enabled = 1,
			.tcpv_rtt = jiffies_to_usecs(ca->rtt),
			.tcpv_minrtt = jiffies_to_usecs(ca->rtt_min),
		};

		nla_put(skb, INET_DIAG_VEGASINFO, sizeof(info), &info);
	}
}


static struct tcp_congestion_ops tcp_westwood __read_mostly = {
	.init		= tcp_westwood_init,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.min_cwnd	= tcp_westwood_bw_rttmin,
	.cwnd_event	= tcp_westwood_event,
	.get_info	= tcp_westwood_info,
	.pkts_acked	= tcp_westwood_pkts_acked,

	.owner		= THIS_MODULE,
	.name		= "westwood"
};

static int __init tcp_westwood_register(void)
{
	BUILD_BUG_ON(sizeof(struct westwood) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_westwood);
}

static void __exit tcp_westwood_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_westwood);
}

module_init(tcp_westwood_register);
module_exit(tcp_westwood_unregister);

MODULE_AUTHOR("Stephen Hemminger, Angelo Dell'Aera");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Westwood+");
