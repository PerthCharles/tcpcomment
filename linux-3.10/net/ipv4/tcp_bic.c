/*
 * Binary Increase Congestion control for TCP
 * Home page:
 *      http://netsrv.csc.ncsu.edu/twiki/bin/view/Main/BIC
 * This is from the implementation of BICTCP in
 * Lison-Xu, Kahaled Harfoush, and Injong Rhee.
 *  "Binary Increase Congestion Control for Fast, Long Distance
 *  Networks" in InfoComm 2004
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/bitcp.pdf
 *
 * Unless BIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <net/tcp.h>


#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define BICTCP_B		4	 /*
					  * In binary search,
					  * go to point (max+min)/N
					  */

static int fast_convergence = 1;
static int max_increment = 16;
static int low_window = 14;
/* 当发送丢包时，将ssthresh设置为当前cwnd的~80% */
static int beta = 819;		/* = 819/1024 (BICTCP_BETA_SCALE) */
static int initial_ssthresh;
static int smooth_part = 20;

module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(max_increment, int, 0644);
MODULE_PARM_DESC(max_increment, "Limit on increment allowed during binary search");
module_param(low_window, int, 0644);
MODULE_PARM_DESC(low_window, "lower bound on congestion window (for TCP friendliness)");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(smooth_part, int, 0644);
MODULE_PARM_DESC(smooth_part, "log(B/(B*Smin))/log(B/(B-1))+B, # of RTT from Wmax-B to Wmax");


/* BIC TCP Parameters */
struct bictcp {
	u32	cnt;		/* increase cwnd by 1 after ACKs */
	u32 	last_max_cwnd;	/* last maximum snd_cwnd */
	u32	loss_cwnd;	/* congestion window at last loss */    /* 在需要undo的时候使用 */
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	epoch_start;	/* beginning of an epoch */         /* 没有被实质性的用到 */
#define ACK_RATIO_SHIFT	4
	u32	delayed_ack;	/* estimate the ratio of Packets/ACKs << 4 */
};

static inline void bictcp_reset(struct bictcp *ca)
{
	ca->cnt = 0;
	ca->last_max_cwnd = 0;
	ca->last_cwnd = 0;
	ca->last_time = 0;
	ca->epoch_start = 0;
	ca->delayed_ack = 2 << ACK_RATIO_SHIFT;
}

static void bictcp_init(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	bictcp_reset(ca);
	ca->loss_cwnd = 0;

	if (initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
}

/*
 * Compute congestion window to use.
 */
/* BIC结构体的更新，算法的关键 */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd)
{
    /* last_cwnd表示上一次更新的cwnd值，last_time表示上一次更新的时间
     * 如果间隔太短，则不更新BIC结构体，也就不会更新cwnd
     * 时间间隔是HZ/32, 即31.25ms 
     * TODO: 这个经验值是怎么来的？ */
	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_time_stamp - ca->last_time) <= HZ / 32)
		return;

    /* 距离上一次更新已经过去了至少31.23ms，故可以再次更新了,做好准备更新的记录 */
	ca->last_cwnd = cwnd;
	ca->last_time = tcp_time_stamp;

	if (ca->epoch_start == 0) /* record the beginning of an epoch */
		ca->epoch_start = tcp_time_stamp;

	/* start off normal */
    /* 如果cwnd还比较小，则与RENO一样, 一个RTT，cwnd增加1 */
	if (cwnd <= low_window) {
		ca->cnt = cwnd;
		return;
	}

	/* binary increase */
    /* 如果cwnd比上一次刚进入快速重传阶段时的cwnd还小 */
	if (cwnd < ca->last_max_cwnd) {
        /* BICTCP_B等于4，并不是严格意义的二分查找 */
		__u32 	dist = (ca->last_max_cwnd - cwnd) / BICTCP_B;

		if (dist > max_increment)
			/* linear increase */
            /* 如果dist超过16，则最大限制成16. 
             * 下式的效果就是：cwnd被分成16分，一个RTT内cwnd能够增加16 */
			ca->cnt = cwnd / max_increment;
		else if (dist <= 1U)
			/* binary search increase */
            /*　如果dist较小，说明已经增加到了上一次刚进入快速重传阶段时的cwnd一样的位置，则放慢cwnd的增长
             * 比如smooth默认是20， BICTCP_B默认是4，则下式的效果是：
             *  5个RTT，cwnd才增长1 */ 
			ca->cnt = (cwnd * smooth_part) / BICTCP_B;
		else
			/* binary search increase */
            /* 下式的效果是：cwnd被分成dist份，一个RTT内cwnd能够增加dist */
			ca->cnt = cwnd / dist;
	} else {
		/* slow start AMD linear increase */
        /* 如果cwnd之比last_max_cwnd大一点点，则5个RTT才将cwnd增加1 */
		if (cwnd < ca->last_max_cwnd + BICTCP_B)
			/* slow start */
			ca->cnt = (cwnd * smooth_part) / BICTCP_B;
        /* 如果 cwnd < last_max_cwnd + 20*3，则3个RTT内cwnd增长dist
         * 这个地方选择三个RTT才增长一个dist，算是一种避免过于激进的策略， */
		else if (cwnd < ca->last_max_cwnd + max_increment*(BICTCP_B-1))
			/* slow start */
			ca->cnt = (cwnd * (BICTCP_B-1))
				/ (cwnd - ca->last_max_cwnd);
        /* 如果cwnd已经很大了，则选择一个RTT内cwnd增长16 */
		else
			/* linear increase */
			ca->cnt = cwnd / max_increment;
	}

	/* if in slow start or link utilization is very low */
    /* 如果没有发生过丢包，那么应该增长的快一些，要做的就是将ca->cnt下降一点
     * 即每收20个ACK，则将cwnd增加1. 从而做到大约5%的增长 */
	if (ca->last_max_cwnd == 0) {
		if (ca->cnt > 20) /* increase cwnd 5% per RTT */
			ca->cnt = 20;
	}

    /* 考虑delay ack的影响
     * 注意：
     *      ca->cnt越小，则cwnd会增长的越快
     *      delay ack机制中限制：在收到两个数据包时，必须立即回复一个ACK */
	ca->cnt = (ca->cnt << ACK_RATIO_SHIFT) / ca->delayed_ack;
	if (ca->cnt == 0)			/* cannot be zero */
		ca->cnt = 1;
}

/* BIC拥塞控制主逻辑 */
static void bictcp_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_slow_start(tp);     /* 慢启动 */
	else {
        /* 拥塞避免，
         * 从实现上看，并不是直接计算出新的snd_cwnd值，
         * 而是计算一个ca->cnt值，然后让它去控制cwnd的增长量 */
		bictcp_update(ca, tp->snd_cwnd);
		tcp_cong_avoid_ai(tp, ca->cnt);
	}

}

/*
 *	behave like Reno until low_window is reached,
 *	then increase congestion window slowly
 */
static u32 bictcp_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->epoch_start = 0;	/* end of epoch */

	/* Wmax and fast convergence */
    /* last_max_cwnd记录刚要进入快速重传/快速恢复阶段时的cwnd值 */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence)
        /* 如果开启fast_convergence，则将last_max_cwnd设置为当前cwnd的 (1024 + 819)/(2*1024) = 89.99% */
		ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE);
	else
		ca->last_max_cwnd = tp->snd_cwnd;

	ca->loss_cwnd = tp->snd_cwnd;


	if (tp->snd_cwnd <= low_window)
        /* 如果cwnd还比较小，则跟reno一样，ssthrehsh设置为cwnd的一半 */
		return max(tp->snd_cwnd >> 1U, 2U);
	else
        /* 否则设置为cwnd的(819/1024) = 79.98% */
		return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U);
}

/* 如果需要undo，返回(当前cwnd)和(进入重传时的cwnd值)中的较大者 */
static u32 bictcp_undo_cwnd(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct bictcp *ca = inet_csk_ca(sk);
	return max(tp->snd_cwnd, ca->loss_cwnd);
}

static void bictcp_state(struct sock *sk, u8 new_state)
{
    /* 如果进入了Loss状态，cwnd会设置为1，然后开启慢启动
     *之前记录的一些last_cwnd之类的参考值的自然也不能用了。 */
	if (new_state == TCP_CA_Loss)
		bictcp_reset(inet_csk_ca(sk));
}

/* Track delayed acknowledgment ratio using sliding window
 * ratio = (15*ratio + sample) / 16
 */
/* cnt是这个ack所确认的数据包的个数
 * 如果delay ack的"每收到两个ACK数据包，必须发送一个ACK"这个原则被遵守，那么cnt应该一直会是0
 * TODO: 这里cnt用的是无符号型，万一cnt等于1，那么是不是有bug ? 尽管做过了平滑 */
static void bictcp_acked(struct sock *sk, u32 cnt, s32 rtt)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ca_state == TCP_CA_Open) {
		struct bictcp *ca = inet_csk_ca(sk);
		cnt -= ca->delayed_ack >> ACK_RATIO_SHIFT;
		ca->delayed_ack += cnt;
	}
}


static struct tcp_congestion_ops bictcp __read_mostly = {
	.init		= bictcp_init,
	.ssthresh	= bictcp_recalc_ssthresh,
	.cong_avoid	= bictcp_cong_avoid,
	.set_state	= bictcp_state,
	.undo_cwnd	= bictcp_undo_cwnd,
	.pkts_acked     = bictcp_acked,
	.owner		= THIS_MODULE,
	.name		= "bic",
};

static int __init bictcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct bictcp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&bictcp);
}

static void __exit bictcp_unregister(void)
{
	tcp_unregister_congestion_control(&bictcp);
}

module_init(bictcp_register);
module_exit(bictcp_unregister);

MODULE_AUTHOR("Stephen Hemminger");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BIC TCP");
