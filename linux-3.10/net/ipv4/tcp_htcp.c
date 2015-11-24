/*
 * H-TCP congestion control. The algorithm is detailed in:
 * R.N.Shorten, D.J.Leith:
 *   "H-TCP: TCP for high-speed and long-distance networks"
 *   Proc. PFLDnet, Argonne, 2004.
 * http://www.hamilton.ie/net/htcp3.pdf
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <net/tcp.h>

#define ALPHA_BASE	(1<<7)	/* 1.0 with shift << 7 */
#define BETA_MIN	(1<<6)	/* 0.5 with shift << 7 */
#define BETA_MAX	102	/* 0.8 with shift << 7 */

static int use_rtt_scaling __read_mostly = 1;
module_param(use_rtt_scaling, int, 0644);
MODULE_PARM_DESC(use_rtt_scaling, "turn on/off RTT scaling");

static int use_bandwidth_switch __read_mostly = 1;
module_param(use_bandwidth_switch, int, 0644);
MODULE_PARM_DESC(use_bandwidth_switch, "turn on/off bandwidth switcher");

struct htcp {
	u32	alpha;		/* Fixed point arith, << 7 */
	u8	beta;           /* Fixed point arith, << 7 */
	u8	modeswitch;	/* Delay modeswitch
				   until we had at least one congestion event */
	u16	pkts_acked;
	u32	packetcount;    /* 每个RTT内确认的数据包个数 */
	u32	minRTT;
	u32	maxRTT;
	u32	last_cong;	/* Time since last congestion event end */
	u32	undo_last_cong;

	u32	undo_maxRTT;
	u32	undo_old_maxB;

	/* Bandwidth estimation */
	u32	minB;
	u32	maxB;
	u32	old_maxB;
	u32	Bi;         /* 平滑过的当前RTT吞吐量，可按照tp->srtt与rttsample的关系理解 */
	u32	lasttime;
};

/* 计算进入当前拥塞周期(epoch)后，经过的时间 */
static inline u32 htcp_cong_time(const struct htcp *ca)
{
	return jiffies - ca->last_cong;
}

/* 计算进入当前拥塞周期(epoch)后，经过的RTT数 */
static inline u32 htcp_ccount(const struct htcp *ca)
{
	return htcp_cong_time(ca) / ca->minRTT;
}

/* 切换到CWR、Recovery、Loss状态前，先保存相关变量
 * 如果后续发现要undo，则要还原 */
static inline void htcp_reset(struct htcp *ca)
{
	ca->undo_last_cong = ca->last_cong;
	ca->undo_maxRTT = ca->maxRTT;
	ca->undo_old_maxB = ca->old_maxB;

	ca->last_cong = jiffies;
}

static u32 htcp_cwnd_undo(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct htcp *ca = inet_csk_ca(sk);

	if (ca->undo_last_cong) {
		ca->last_cong = ca->undo_last_cong;
		ca->maxRTT = ca->undo_maxRTT;
		ca->old_maxB = ca->undo_old_maxB;
		ca->undo_last_cong = 0;
	}

	return max(tp->snd_cwnd, (tp->snd_ssthresh << 7) / ca->beta);
}

/* 每次收到ACK包都会被调用，用于更新minRTT和maxRTT
 * 这里传入的参数并没有<<3，取名为srtt容易让人产生误解 */
static inline void measure_rtt(struct sock *sk, u32 srtt)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct htcp *ca = inet_csk_ca(sk);

	/* keep track of minimum RTT seen so far, minRTT is zero at first */
	if (ca->minRTT > srtt || !ca->minRTT)
		ca->minRTT = srtt;

	/* max RTT */
    /* 只能在open状态采样，处于其他状态可能会得到过大的值 */
	if (icsk->icsk_ca_state == TCP_CA_Open) {
		if (ca->maxRTT < ca->minRTT)
			ca->maxRTT = ca->minRTT;

        /* 进一步保守的更新maxRTT：如果传入的rtt sample值超过当前maxRTT过多(20ms)，也不信任这个rtt sample */
		if (ca->maxRTT < srtt &&
		    srtt <= ca->maxRTT + msecs_to_jiffies(20))
			ca->maxRTT = srtt;
	}
}

/* 每收到一个ACK时调用, 主要用于更新当前epoch的最大吞吐量maxB
 * 注意rtt并没有<<3，因此传给measure_rtt()的参数也没有<<3 */
static void measure_achieved_throughput(struct sock *sk, u32 pkts_acked, s32 rtt)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	struct htcp *ca = inet_csk_ca(sk);
	u32 now = tcp_time_stamp;

    /* 仅记录在open状态下，被ack的数目 */
	if (icsk->icsk_ca_state == TCP_CA_Open)
		ca->pkts_acked = pkts_acked;

    /* 获得有效rtt sample后，更新minRTT和maxRTT */
	if (rtt > 0)
		measure_rtt(sk, usecs_to_jiffies(rtt));

    /* use_bandwidth_switch表示是否需要检查不同epoch中吞吐量的变化来调整beta，默认开启
     * 如果不开启，则不需要接着计算吞吐量了 */
	if (!use_bandwidth_switch)
		return;

	/* achieved throughput calculations */
    /* 只在open或disorder状态下才计算当前吞吐量 */
	if (!((1 << icsk->icsk_ca_state) & (TCPF_CA_Open | TCPF_CA_Disorder))) {
		ca->packetcount = 0;    /* 清零统计的被确认的数据包个数 */
		ca->lasttime = now;     /* 记录开始统计被确认的数据包个数的时间, 可理解为当前RTT周期的开始时间，也可理解为上一个RTT周期的结束时间 */
		return;
	}

	ca->packetcount += pkts_acked;

    /* 在每个RTT周期结束时，才计算吞吐量 */
	if (ca->packetcount >= tp->snd_cwnd - (ca->alpha >> 7 ? : 1) &&
	    now - ca->lasttime >= ca->minRTT &&
	    ca->minRTT > 0) {
        /* 当前RTT内的吞吐量 */
		__u32 cur_Bi = ca->packetcount * HZ / (now - ca->lasttime);

        /* 如果距离上次丢包的时间不超过3个minRTT,则更新吞吐量相关数据
         * 内在含义：只有等正常发送数据足够久了，才信任cur_Bi的采样 */
		if (htcp_ccount(ca) <= 3) {
			/* just after backoff */
			ca->minB = ca->maxB = ca->Bi = cur_Bi;
		} else {
			ca->Bi = (3 * ca->Bi + cur_Bi) / 4;     /* 对cur_Bi进行平滑处理 */
			if (ca->Bi > ca->maxB)
				ca->maxB = ca->Bi;      /* 更新最大吞吐量 */
			if (ca->minB > ca->maxB)    /* minB是完全多余的变量，不用管它 */
				ca->minB = ca->maxB;
		}
        /* 一个RTT周期结束后，开始新的统计周期 */
		ca->packetcount = 0;
		ca->lasttime = now;
	}
}

/* 更新AIMD中的md值，即ca->beta值。
 * 仅在刚要进入快速重传/快速恢复的时候才计算 */
static inline void htcp_beta_update(struct htcp *ca, u32 minRTT, u32 maxRTT)
{
    /* 如果要根据吞吐量的变化，来调整beta */
	if (use_bandwidth_switch) {
		u32 maxB = ca->maxB;
		u32 old_maxB = ca->old_maxB;
		ca->old_maxB = ca->maxB;    /* 快要结束一个拥塞周期(epoch)了，用old_maxB记录快要结束的epoch的最大吞吐量 */

        /* 判断下式是否成立：
         *     4old_maxB <= 5maxB <= 6old_maxB
         *  如果成立，则意味着： -old_maxB <= 5(maxB - old_maxB) <= old_maxB, 即 |maxB - old_maxB| <= 20% old_maxB
         *
         *  如果不成立，就说明新一个epoch的最大吞吐量变化较大，可能是链路发生了变化，
         *  因此需要快速收敛，从而将beta设置为0.5 */
		if (!between(5 * maxB, 4 * old_maxB, 6 * old_maxB)) {
			ca->beta = BETA_MIN;
            /* 这个变量的作用：使下一个epoch继续使用beta=0.5，来保证快速收敛 */
			ca->modeswitch = 0;
			return;
		}
	}

    /* 记录modeswitch的作用：使下一个epoch继续使用beta=0.5，来保证快速收敛 */
    /* minRTT超过10ms才能使用，防止RTT过小 */
	if (ca->modeswitch && minRTT > msecs_to_jiffies(10) && maxRTT) {
        /* 另外要记住： beta是经历了<< 7的 */
		ca->beta = (minRTT << 7) / maxRTT;
        /* 限制beta的取值区间为 [0.5, 0.8] */
		if (ca->beta < BETA_MIN)
			ca->beta = BETA_MIN;
		else if (ca->beta > BETA_MAX)
			ca->beta = BETA_MAX;
	} else {
		ca->beta = BETA_MIN;
		ca->modeswitch = 1;
	}
}

/* 更新AIMD中的ai值, 即ca->alpha值 */
static inline void htcp_alpha_update(struct htcp *ca)
{
	u32 minRTT = ca->minRTT;
	u32 factor = 1;
	u32 diff = htcp_cong_time(ca);

    /* 如果进入当前拥塞周期(epoch)超过了一秒，则使用更大的factor值用于更新ca->alpha值 */
	if (diff > HZ) {
		diff -= HZ;
        /* 论文中的计算公式： factor = 1 + 10 * (t - delta) + ((t-delta)/2)^2
         * diff 就是上式中的t-delta, 实现中除以HZ因为diff还是jiffies的单位，要转换成秒 */
		factor = 1 + (10 * diff + ((diff / 2) * (diff / 2) / HZ)) / HZ;
	}

    /* use_rtt_scaling表示是否根据rtt来进一步调节alpha值, 默认开启 */
	if (use_rtt_scaling && minRTT) {
        /* 理解代码时，先不考虑限制scale范围部分，将两个计算步骤合并一下得到：
         * factor = (factor << 3) * (10 *minRTT) / (HZ << 3)
         * 可见minRTT越大，factor被放大的倍数越多，再结合对于scale值的限制可得以下结论
         * 1. minRTT > 200ms时，scale被限制为0.5，从而factor被放大2倍
         * 2. minRTT < 10ms时，scale被限制为10, 从而factor被放大0.1倍 -- 缩小10倍
         * 内在逻辑：RTT越大，alpha应该越大 */
		u32 scale = (HZ << 3) / (10 * minRTT);

		/* clamping ratio to interval [0.5,10]<<3 */
		scale = min(max(scale, 1U << 2), 10U << 3);
		factor = (factor << 3) / scale;
        /* factor在minRTT较小时，可能被缩小，但也要限制最小值为1 */
		if (!factor)
			factor = 1;
	}

    /* 论文中的计算公式： alpha = 2 * factor * (1 - beta)
     * 由于beta的大小限制在[0.5, 0.8] 所以这个地方只会较小alpha
     * 内在逻辑：如果beta越大，说明maxRTT越接近minRTT，说明网络中几乎没有排队,
     * htcp选择此时适当的减小alpha值。  TODO：为什么要这样做 ? */
	ca->alpha = 2 * factor * ((1 << 7) - ca->beta);
	if (!ca->alpha)
		ca->alpha = ALPHA_BASE;
}

/*
 * After we have the rtt data to calculate beta, we'd still prefer to wait one
 * rtt before we adjust our beta to ensure we are working from a consistent
 * data.
 *
 * This function should be called when we hit a congestion event since only at
 * that point do we really have a real sense of maxRTT (the queues en route
 * were getting just too full now).
 */
static void htcp_param_update(struct sock *sk)
{
	struct htcp *ca = inet_csk_ca(sk);
	u32 minRTT = ca->minRTT;
	u32 maxRTT = ca->maxRTT;

    /* 更新AIMD的ai和md值 */
	htcp_beta_update(ca, minRTT, maxRTT);
	htcp_alpha_update(ca);

	/* add slowly fading memory for maxRTT to accommodate routing changes */
    /* 稍微减小一下maxRTT: max = 0.95max + 0.05min */
	if (minRTT > 0 && maxRTT > minRTT)
		ca->maxRTT = minRTT + ((maxRTT - minRTT) * 95) / 100;
}

/* 需要重新计算慢启动阈值时调用，一般情况为：即将进入快速重传/快速恢复阶段 */
static u32 htcp_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct htcp *ca = inet_csk_ca(sk);

    /* 主要是计算beta值，也会顺道更新alpha值 */
	htcp_param_update(sk);
    /* 使用beta设置ssthresh */
	return max((tp->snd_cwnd * ca->beta) >> 7, 2U);
}

/* htcp算法的主逻辑 */
static void htcp_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct htcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_slow_start(tp);     /* 慢启动 */
	else {
		/* In dangerous area, increase slowly.
		 * In theory this is tp->snd_cwnd += alpha / tp->snd_cwnd
		 */
        /* 转换一下可能比较好理解：
         *      snd_cwnd_cnt >= snd_cwnd / ai, 则snd_cwnd++
         *      效果就是一个RTT内，cwnd会增加ai个单位 */
		if ((tp->snd_cwnd_cnt * ca->alpha)>>7 >= tp->snd_cwnd) {
			if (tp->snd_cwnd < tp->snd_cwnd_clamp)
				tp->snd_cwnd++;
			tp->snd_cwnd_cnt = 0;
			htcp_alpha_update(ca);  /* 更新AIMD的ai值。cwnd更新一次，该值也更新一次 */
		} else
			tp->snd_cwnd_cnt += ca->pkts_acked;

		ca->pkts_acked = 1;
	}
}

/* 算法初始化 */
static void htcp_init(struct sock *sk)
{
	struct htcp *ca = inet_csk_ca(sk);

	memset(ca, 0, sizeof(struct htcp));
	ca->alpha = ALPHA_BASE;     /* AIMD策略中的ai值(<<7)，默认最小值 1 */
	ca->beta = BETA_MIN;        /* AIMD策略中的md值(<<7)，默认最小值0.5 */
	ca->pkts_acked = 1;         /* 每个ack确认的包数目，默认为1.  -- 该值会在每收到一个ACK时进行更新，设置为1算是设置下限 */
	ca->last_cong = jiffies;    /* 可理解为cubic中的epoch，每次epoch的起点 */
}

static void htcp_state(struct sock *sk, u8 new_state)
{
	switch (new_state) {
	case TCP_CA_Open:
		{
			struct htcp *ca = inet_csk_ca(sk);
            /* 清楚undo相关信息 */
			if (ca->undo_last_cong) {
				ca->last_cong = jiffies;
				ca->undo_last_cong = 0;
			}
		}
		break;
	case TCP_CA_CWR:
	case TCP_CA_Recovery:
	case TCP_CA_Loss:
		htcp_reset(inet_csk_ca(sk));
		break;
	}
}

static struct tcp_congestion_ops htcp __read_mostly = {
	.init		= htcp_init,
	.ssthresh	= htcp_recalc_ssthresh,
	.cong_avoid	= htcp_cong_avoid,
	.set_state	= htcp_state,
	.undo_cwnd	= htcp_cwnd_undo,
	.pkts_acked	= measure_achieved_throughput,
	.owner		= THIS_MODULE,
	.name		= "htcp",
};

static int __init htcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct htcp) > ICSK_CA_PRIV_SIZE);
	BUILD_BUG_ON(BETA_MIN >= BETA_MAX);
	return tcp_register_congestion_control(&htcp);
}

static void __exit htcp_unregister(void)
{
	tcp_unregister_congestion_control(&htcp);
}

module_init(htcp_register);
module_exit(htcp_unregister);

MODULE_AUTHOR("Baruch Even");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("H-TCP");
