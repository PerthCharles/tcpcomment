/*
 * TCP CUBIC: Binary Increase Congestion control for TCP v2.3
 * Home page:
 *      http://netsrv.csc.ncsu.edu/twiki/bin/view/Main/BIC
 * This is from the implementation of CUBIC TCP in
 * Sangtae Ha, Injong Rhee and Lisong Xu,
 *  "CUBIC: A New TCP-Friendly High-Speed TCP Variant"
 *  in ACM SIGOPS Operating System Review, July 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/cubic_a_new_tcp_2008.pdf
 *
 * CUBIC integrates a new slow start algorithm, called HyStart.
 * The details of HyStart are presented in
 *  Sangtae Ha and Injong Rhee,
 *  "Taming the Elephants: New TCP Slow Start", NCSU TechReport 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/hystart_techreport_2008.pdf
 *
 * All testing results are available from:
 * http://netsrv.csc.ncsu.edu/wiki/index.php/TCP_Testing
 *
 * Unless CUBIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>

#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
/* 本来应该是jiffies/HZ,单位为秒。但秒粒度太大，影响计算精确度。
 * 所以计算式先把时间放大2^10倍 */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
/* hystart中两种推出检测需要推出慢启动阶段的方法 */
/* 一个ACK TRAIN一般可以认为是一个cwnd窗口内发送的数据包，
 * 因此如果一个ACK TRAIN的长度达到了min_rtt的长度，说明
 * 当前cwnd已经能够充分利用带宽，几乎跑满BDP，进而可以选择推出慢启动 */
#define HYSTART_ACK_TRAIN	0x1
/* 在启用该方法时，如果delay出现大幅度的增长，则说明快要或者已经出现拥塞，hystart就选择退出慢启动阶段 */
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4U<<3)
#define HYSTART_DELAY_MAX	(16U<<3)
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)

static int fast_convergence __read_mostly = 1;
static int beta __read_mostly = 717;	/* = 717/1024 (BICTCP_BETA_SCALE) */
static int initial_ssthresh __read_mostly;
static int bic_scale __read_mostly = 41;
static int tcp_friendliness __read_mostly = 1;

static int hystart __read_mostly = 1;
static int hystart_detect __read_mostly = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_low_window __read_mostly = 16;
static int hystart_ack_delta __read_mostly = 2;

static u32 cube_rtt_scale __read_mostly;
static u32 beta_scale __read_mostly;
static u64 cube_factor __read_mostly;

/* Note parameters that are used for precomputing scale factors are read-only */
module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(bic_scale, int, 0444);
MODULE_PARM_DESC(bic_scale, "scale (scaled by 1024) value for bic function (bic_scale/1024)");
module_param(tcp_friendliness, int, 0644);
MODULE_PARM_DESC(tcp_friendliness, "turn on/off tcp friendliness");
module_param(hystart, int, 0644);
MODULE_PARM_DESC(hystart, "turn on/off hybrid slow start algorithm");
module_param(hystart_detect, int, 0644);
MODULE_PARM_DESC(hystart_detect, "hyrbrid slow start detection mechanisms"
		 " 1: packet-train 2: delay 3: both packet-train and delay");
module_param(hystart_low_window, int, 0644);
MODULE_PARM_DESC(hystart_low_window, "lower bound cwnd for hybrid slow start");
module_param(hystart_ack_delta, int, 0644);
MODULE_PARM_DESC(hystart_ack_delta, "spacing between ack's indicating train (msecs)");

/* BIC TCP Parameters */
struct bictcp {
	u32	cnt;		/* increase cwnd by 1 after ACKs */ /* 用于控制snd_cwnd的增长速度 */
	u32 	last_max_cwnd;	/* last maximum snd_cwnd */
	u32	loss_cwnd;	/* congestion window at last loss */
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	bic_origin_point;/* origin point of bic function */
	u32	bic_K;		/* time to origin point from the beginning of the current epoch */
	u32	delay_min;	/* min delay (msec << 3) */
	u32	epoch_start;	/* beginning of an epoch */
	u32	ack_cnt;	/* number of acks */
	u32	tcp_cwnd;	/* estimated tcp cwnd */
#define ACK_RATIO_SHIFT	4
#define ACK_RATIO_LIMIT (32u << ACK_RATIO_SHIFT)
	u16	delayed_ack;	/* estimate the ratio of Packets/ACKs << 4 */
	u8	sample_cnt;	/* number of samples to decide curr_rtt */
	u8	found;		/* the exit point is found? */
	u32	round_start;	/* beginning of each round */
	u32	end_seq;	/* end_seq of the round */
	u32	last_ack;	/* last time when the ACK spacing is close */
	u32	curr_rtt;	/* the minimum rtt of current round */
};

static inline void bictcp_reset(struct bictcp *ca)
{
	ca->cnt = 0;
	ca->last_max_cwnd = 0;
	ca->last_cwnd = 0;
	ca->last_time = 0;
	ca->bic_origin_point = 0;
	ca->bic_K = 0;
	ca->delay_min = 0;
	ca->epoch_start = 0;
	ca->delayed_ack = 2 << ACK_RATIO_SHIFT;
	ca->ack_cnt = 0;
	ca->tcp_cwnd = 0;
	ca->found = 0;
}

static inline u32 bictcp_clock(void)
{
#if HZ < 1000
	return ktime_to_ms(ktime_get_real());
#else
	return jiffies_to_msecs(jiffies);
#endif
}

static inline void bictcp_hystart_reset(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->round_start = ca->last_ack = bictcp_clock();
	ca->end_seq = tp->snd_nxt;
	ca->curr_rtt = 0;
	ca->sample_cnt = 0;
}

static void bictcp_init(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	bictcp_reset(ca);
	ca->loss_cwnd = 0;

    /* 如果开启hybird slow start(默认开启), 则进行相关变量的初始化 */
	if (hystart)
		bictcp_hystart_reset(sk);

    /* 如果没有开启hystart, 同时在加载CUBIC模块时有指定了ssthresh */
	if (!hystart && initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
}

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32)v[(u32)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

/*
 * Compute congestion window to use.
 */
/* cubic算法的核心逻辑
 * cubic计算cwnd的基本公式：
 *      W_cubic = C * (t - K)^3 + W_max     (1)
 *  其中，C是乘法因子，t是距离上一次cwnd reduction的时间，W_max是上一次cwnd_reduction时的cwnd值
 *      K = cubic_root[(W_max*beta) / C], 其中beta是cwnd的进入快速重传时的下降因子
 *
 *  而K的值是根据初始的W_cubic和W_max值，在刚进入拥塞避免时(t=0)计算得到的, 进而由公式(1)可得：
 *      K = cubic_root[(W_cubic - W_max)/C]
 *
 *  结合代码实现，以上参数在实现中分别对应如下
 *  calculate the "K" for (wmax-cwnd) = c/rtt * K^3
 *       *  so K = cubic_root( (wmax-cwnd)*rtt/c )
 *
 *      C = bic_scale >> 10 约为0.04
 *          1. 但由于t和K为了精度都放大了(2^BICTCP_HZ)倍，所以C应该缩小(2^BICTCP_HZ)^3倍，即2^30倍
 *             故实现中参与计算的C = (41 >> 10)/(2^30) = 41 / 2^40
 *          2. 实现中利用的公式其实还考虑了RTT，具体用的公式为： W_cubic = (C/rtt) * (t - K)^3 + W_max
 *             而实现中默认使用的rtt为100ms，化为秒的话，C还应该乘以10，即变量cube_rtt_scale
 *             故真实参与计算bic_K的C值为 (41 * 10) / 2^40 ，即cube_factor
 *
 *      W_max的变量名称为：bic_origin_point，含义就是y=x^3坐标系原点的cwnd值
 *      beta = 717/1024 约为 0.7
 *      K的变量名称为bic_K，表示y=x^3函数曲线在坐标系中向右平移了bic_K个时间单位  */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd)
{
	u64 offs;
    /* delta是cwnd差， bic_target是预期的cwnd值，t为预测时间 */
	u32 delta, t, bic_target, max_cnt;

	ca->ack_cnt++;	/* count the number of ACKs */

    /* 与bic一样，如果31.25ms内，cwnd都没有增长，则直接返回 
     * TODO: 目的是给足够的时间，让snd_cwnd_cnt增长到ca->cnt，从而使cwnd符合算法预期的进行增长? */
	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_time_stamp - ca->last_time) <= HZ / 32)
		return;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_time_stamp;

    /* 开始一个全新的epoch，epoch的理解如下
     * 1. 当发生丢包要进入快速重传，则结束epoch
     * 2. 当进入loss阶段后，会重置epoch_start，结束epoch
     * -- 综上，epoch可以理解为一段连续的拥塞避免阶段, 期间未发生丢包 */
	if (ca->epoch_start == 0) {
		ca->epoch_start = tcp_time_stamp;	/* record the beginning of an epoch */
		ca->ack_cnt = 1;			/* start counting */
		ca->tcp_cwnd = cwnd;			/* syn with cubic */    /* 将ca->tcp_cwnd与实际作用的cwnd进行同步 */

        /* 取max(last_max_cwnd, cwnd)作为当前的Wmax, 在CUBIC中叫bic_origin_point
         * 可以理解为y=x^3这个函数所在坐标系的原点的cwnd值, 要注意这个origin_point只会在开始一个新的epoch才会设置 */
		if (ca->last_max_cwnd <= cwnd) {
            /* 由于origin point设置为当前cwnd，所以预期的cwn变化曲线y=x^3不需要在坐标系中的进行平移 */
			ca->bic_K = 0;      
			ca->bic_origin_point = cwnd;
		} else {
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
            /* cube_factor在注册cubic算法的时候，计算的值是: cube_factor = 2^40 / (41 * 10)
             * 至于cube_factor为什么是这个值，请查看函数开始部分的注释 */
			ca->bic_K = cubic_root(cube_factor
					       * (ca->last_max_cwnd - cwnd));
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	/* change the unit from HZ to bictcp_HZ */
    /* 计算当前时间与epoch开始的时间差，即论文公式中的t */
	t = ((tcp_time_stamp + msecs_to_jiffies(ca->delay_min>>3)
	      - ca->epoch_start) << BICTCP_HZ) / HZ;

    /* 计算 | t - K | */
	if (t < ca->bic_K)		/* t - K */
		offs = ca->bic_K - t;
	else
		offs = t - ca->bic_K;

    /* 计算cubic算法预期调整到的cwnd值：bic_target */
	/* c/rtt * (t-K)^3 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
	if (t < ca->bic_K)                                	/* below origin*/
		bic_target = ca->bic_origin_point - delta;
	else                                                	/* above origin*/
		bic_target = ca->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd) {
		ca->cnt = cwnd / (bic_target - cwnd);   /* 设置ca->cnt，使得一个RTT内，cwnd增长 (bic_target - cwnd) */
	} else {
        /* 如果cwnd已经超于预期了，则应该降速，即100RTT才增加1个单位  -- 基本上等于保持不变 */
		ca->cnt = 100 * cwnd;              /* very small increment*/
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
    /* 如果有慢启动，然后计入拥塞避免，last_max_cwnd是没有设置的，此时可能还没有充分利用带宽
     * (比如ssthresh错误的配置,或hystart过早的触发了)
     * 此时为了保障能尽快的利用满带宽，设置cwnd的最小增速为 5% per RTT */
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

	/* TCP Friendly */
    /* 默认开启 */
	if (tcp_friendliness) {
		u32 scale = beta_scale;
        /* 有beta_scale的计算公式，可得delta的公式为：
         * {(BICTCP_BETA_SCALE + beta) / [3 * (BICTCP_BETA_SCALE - beta)]} * cwnd
         */
        /* 至于delta为什么是这个值，可以看cubic的论文，它给出的一个理论结论就是：
         *      the TCP-fair additive increment would be 3(1-beta)/(1+beta) per RTT
         * 那么如果要与它产生一致的效果，ack_cnt应该等于 cwnd / [3(1-beta)/(1+beta)], 变换一下就是delta的式子 */
		delta = (cwnd * scale) >> 3;
		while (ca->ack_cnt > delta) {		/* update tcp cwnd */
			ca->ack_cnt -= delta;
			ca->tcp_cwnd++;
		}
        /* 如果cubic的cwnd比reno的还慢，则要提高速度了cwnd的速度了 */
		if (ca->tcp_cwnd > cwnd){	/* if bic is slower than tcp */
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

    /* 考虑delay ack：比如接收方是收两个数据包发送一个ACK，那么ca->cnt则还要除以2才能match好 */
	ca->cnt = (ca->cnt << ACK_RATIO_SHIFT) / ca->delayed_ack;
	if (ca->cnt == 0)			/* cannot be zero */
		ca->cnt = 1;
}

/* cubic拥塞算法的主逻辑 */
static void bictcp_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	if (tp->snd_cwnd <= tp->snd_ssthresh) {
        /* 一个RTT结束，开启一个新的RTT时 重传设置hystart中的变量 */
		if (hystart && after(ack, ca->end_seq))
			bictcp_hystart_reset(sk);
		tcp_slow_start(tp);
	} else {
		bictcp_update(ca, tp->snd_cwnd);
		tcp_cong_avoid_ai(tp, ca->cnt);
	}

}

static u32 bictcp_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->epoch_start = 0;	/* end of epoch */

	/* Wmax and fast convergence */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence)
		ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE);
	else
		ca->last_max_cwnd = tp->snd_cwnd;

	ca->loss_cwnd = tp->snd_cwnd;   /* 要进入重传，则设置loss_cwnd记录刚要进入重传阶段是的cwnd，本质是用于undo时恢复cwnd */

	return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U);
}

static u32 bictcp_undo_cwnd(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

static void bictcp_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss) {
		bictcp_reset(inet_csk_ca(sk));
		bictcp_hystart_reset(sk);
	}
}

/* 判断是否需要推出慢启动阶段的核心逻辑
 * 如果判断出要退出慢启动，则将sstresh设置为cwnd即可 */
static void hystart_update(struct sock *sk, u32 delay)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

    /* 如果没发现要退出慢启动的证据，在接着找证据 */
	if (!(ca->found & hystart_detect)) {
		u32 now = bictcp_clock();

		/* first detection parameter - ack-train detection */
        /* 如果两个ACK之间的间隔小于hystart_ack_delta(2ms),则认为这两个ACK属于一辆ACK-TRAIN */
		if ((s32)(now - ca->last_ack) <= hystart_ack_delta) {
			ca->last_ack = now; /* 更新train的最后一个时间戳 */
            /* 如果ACK TRAIN的总时间长度，超过min-rtt/2，则认为应该退出慢启动了
             * 为什么是1/2，因为ACK只会在receiver->sender的这个方向上，ACK-TRAIN最多
             * 只能占满半个RTT */
			if ((s32)(now - ca->round_start) > ca->delay_min >> 4)
				ca->found |= HYSTART_ACK_TRAIN;
		}

		/* obtain the minimum delay of more than sampling packets */
        /* 至少获得8个rtt采样后，才开始使用delay来判断 */
		if (ca->sample_cnt < HYSTART_MIN_SAMPLES) {
			if (ca->curr_rtt == 0 || ca->curr_rtt > delay)
				ca->curr_rtt = delay;

			ca->sample_cnt++;
		} else {
            /* curr_rtt实际上存的是8*rtt,因此下面这个式子就是：
             * 8*new-rtt > 8 * min-rtt + min(8*16, max(8*4, min-rtt/2))
             * 两边都除以8,就跟论文中的式子差不多了，就是min和max从2,8变成了4,16 */
            /* 内在含义就是：rtt增大的太多了，该退出慢启动了 */
			if (ca->curr_rtt > ca->delay_min +
			    HYSTART_DELAY_THRESH(ca->delay_min>>4))
				ca->found |= HYSTART_DELAY;
		}
		/*
		 * Either one of two conditions are met,
		 * we exit from slow start immediately.
		 */
        /* 将慢启动阈值调到cwnd，则之后就会退出慢启动过程，而进入拥塞避免阶段 */
		if (ca->found & hystart_detect)
			tp->snd_ssthresh = tp->snd_cwnd;
	}
}

/* Track delayed acknowledgment ratio using sliding window
 * ratio = (15*ratio + sample) / 16
 */
static void bictcp_acked(struct sock *sk, u32 cnt, s32 rtt_us)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 delay;

	if (icsk->icsk_ca_state == TCP_CA_Open) {
		u32 ratio = ca->delayed_ack;

		ratio -= ca->delayed_ack >> ACK_RATIO_SHIFT;
		ratio += cnt;

		ca->delayed_ack = min(ratio, ACK_RATIO_LIMIT);
	}

	/* Some calls are for duplicates without timetamps */
	if (rtt_us < 0)
		return;

	/* Discard delay samples right after fast recovery */
    /* 快速恢复的1s内不进行采样 */
	if ((s32)(tcp_time_stamp - ca->epoch_start) < HZ)
		return;

    /* rtt_us是一次RTT sample值，单位是us 
     * delay的单位则是ms，而且左移了3位(这点与srtt的存储类似) */
	delay = (rtt_us << 3) / USEC_PER_MSEC;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	if (ca->delay_min == 0 || ca->delay_min > delay)
		ca->delay_min = delay;

	/* hystart triggers when cwnd is larger than some threshold */
    /* 如果启用了hystart,如果在慢启动阶段，且cwnd已经超过了启动hystart的下限，
     * 则启动hystart机制，检测是否应该推出慢启动阶段了 */
	if (hystart && tp->snd_cwnd <= tp->snd_ssthresh &&
	    tp->snd_cwnd >= hystart_low_window)
		hystart_update(sk, delay);
}

static struct tcp_congestion_ops cubictcp __read_mostly = {
	.init		= bictcp_init,
	.ssthresh	= bictcp_recalc_ssthresh,
	.cong_avoid	= bictcp_cong_avoid,
	.set_state	= bictcp_state,
	.undo_cwnd	= bictcp_undo_cwnd,
	.pkts_acked     = bictcp_acked,
	.owner		= THIS_MODULE,
	.name		= "cubic",
};

static int __init cubictcp_register(void)
{
    /* 拥塞控制算法使用的参数不能太多，不得超过struct inet_connection_sock 中预留的长度 */
	BUILD_BUG_ON(sizeof(struct bictcp) > ICSK_CA_PRIV_SIZE);

	/* Precompute a bunch of the scaling factors that are used per-packet
	 * based on SRTT of 100ms
	 */

    /* 默认值: beta_scale = 15 */
	beta_scale = 8*(BICTCP_BETA_SCALE+beta)/ 3 / (BICTCP_BETA_SCALE - beta);

    /* 默认值： 410 */
	cube_rtt_scale = (bic_scale * 10);	/* 1024*c/rtt */

	/* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
	 *  so K = cubic_root( (wmax-cwnd)*rtt/c )
	 * the unit of K is bictcp_HZ=2^10, not HZ
	 *
	 *  c = bic_scale >> 10
	 *  c = 41 >> 10 约为0.04
	 *  rtt = 100ms
	 *
	 * the following code has been designed and tested for
	 * cwnd < 1 million packets
	 * RTT < 100 seconds
	 * HZ < 1,000,00  (corresponding to 10 nano-second)
	 */

	/* 1/c * 2^2*bictcp_HZ * srtt */
	cube_factor = 1ull << (10+3*BICTCP_HZ); /* 2^40 */

	/* divide by bic_scale and by constant Srtt (100ms) */
    /* do_div(x, y)的效果是将x/y的结果存入x中，x%y的结果作为返回值 */
    /* cube_factor = 2^40 / (41 * 10) */
	do_div(cube_factor, bic_scale * 10);

	/* hystart needs ms clock resolution */
	if (hystart && HZ < 1000)
		cubictcp.flags |= TCP_CONG_RTT_STAMP;

	return tcp_register_congestion_control(&cubictcp);
}

static void __exit cubictcp_unregister(void)
{
	tcp_unregister_congestion_control(&cubictcp);
}

module_init(cubictcp_register);
module_exit(cubictcp_unregister);

MODULE_AUTHOR("Sangtae Ha, Stephen Hemminger");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CUBIC TCP");
MODULE_VERSION("2.3");
