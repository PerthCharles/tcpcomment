/*
 * Sally Floyd's High Speed TCP (RFC 3649) congestion control
 *
 * See http://www.icir.org/floyd/hstcp.html
 *
 * John Heffner <jheffner@psc.edu>
 */

#include <linux/module.h>
#include <net/tcp.h>


/* From AIMD tables from RFC 3649 appendix B,
 * with fixed-point MD scaled <<8.
 */
/* 可以把hstcp_aimd_vals[]看成一个分段函数，自变量是cwnd，值为md
 * 那ai值是怎么定的呢？
 * 答：查找hstcp_aimd_vals[]，找到满足下面条件的ai
 *     hstcp_aimd_vals[ai-1] < snd_cwnd < hstcp_aimd_vals[ai] */
static const struct hstcp_aimd_val {
	unsigned int cwnd;  /* 区间分隔点 */
	unsigned int md;    /* 放大256倍的MD因子,趋势是cwnd越大，MD越小 */
} hstcp_aimd_vals[] = {
 {     38,  128, /*  0.50 */ },
 {    118,  112, /*  0.44 */ },
 {    221,  104, /*  0.41 */ },
 {    347,   98, /*  0.38 */ },
 {    495,   93, /*  0.37 */ },
 {    663,   89, /*  0.35 */ },
 {    851,   86, /*  0.34 */ },
 {   1058,   83, /*  0.33 */ },
 {   1284,   81, /*  0.32 */ },
 {   1529,   78, /*  0.31 */ },
 {   1793,   76, /*  0.30 */ },
 {   2076,   74, /*  0.29 */ },
 {   2378,   72, /*  0.28 */ },
 {   2699,   71, /*  0.28 */ },
 {   3039,   69, /*  0.27 */ },
 {   3399,   68, /*  0.27 */ },
 {   3778,   66, /*  0.26 */ },
 {   4177,   65, /*  0.26 */ },
 {   4596,   64, /*  0.25 */ },
 {   5036,   62, /*  0.25 */ },
 {   5497,   61, /*  0.24 */ },
 {   5979,   60, /*  0.24 */ },
 {   6483,   59, /*  0.23 */ },
 {   7009,   58, /*  0.23 */ },
 {   7558,   57, /*  0.22 */ },
 {   8130,   56, /*  0.22 */ },
 {   8726,   55, /*  0.22 */ },
 {   9346,   54, /*  0.21 */ },
 {   9991,   53, /*  0.21 */ },
 {  10661,   52, /*  0.21 */ },
 {  11358,   52, /*  0.20 */ },
 {  12082,   51, /*  0.20 */ },
 {  12834,   50, /*  0.20 */ },
 {  13614,   49, /*  0.19 */ },
 {  14424,   48, /*  0.19 */ },
 {  15265,   48, /*  0.19 */ },
 {  16137,   47, /*  0.19 */ },
 {  17042,   46, /*  0.18 */ },
 {  17981,   45, /*  0.18 */ },
 {  18955,   45, /*  0.18 */ },
 {  19965,   44, /*  0.17 */ },
 {  21013,   43, /*  0.17 */ },
 {  22101,   43, /*  0.17 */ },
 {  23230,   42, /*  0.17 */ },
 {  24402,   41, /*  0.16 */ },
 {  25618,   41, /*  0.16 */ },
 {  26881,   40, /*  0.16 */ },
 {  28193,   39, /*  0.16 */ },
 {  29557,   39, /*  0.15 */ },
 {  30975,   38, /*  0.15 */ },
 {  32450,   38, /*  0.15 */ },
 {  33986,   37, /*  0.15 */ },
 {  35586,   36, /*  0.14 */ },
 {  37253,   36, /*  0.14 */ },
 {  38992,   35, /*  0.14 */ },
 {  40808,   35, /*  0.14 */ },
 {  42707,   34, /*  0.13 */ },
 {  44694,   33, /*  0.13 */ },
 {  46776,   33, /*  0.13 */ },
 {  48961,   32, /*  0.13 */ },
 {  51258,   32, /*  0.13 */ },
 {  53677,   31, /*  0.12 */ },
 {  56230,   30, /*  0.12 */ },
 {  58932,   30, /*  0.12 */ },
 {  61799,   29, /*  0.12 */ },
 {  64851,   28, /*  0.11 */ },
 {  68113,   28, /*  0.11 */ },
 {  71617,   27, /*  0.11 */ },
 {  75401,   26, /*  0.10 */ },
 {  79517,   26, /*  0.10 */ },
 {  84035,   25, /*  0.10 */ },
 {  89053,   24, /*  0.10 */ },
};

#define HSTCP_AIMD_MAX	ARRAY_SIZE(hstcp_aimd_vals)

struct hstcp {
	u32	ai;     /* AIMD中的ai */
};

static void hstcp_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct hstcp *ca = inet_csk_ca(sk);

	ca->ai = 0;

	/* Ensure the MD arithmetic works.  This is somewhat pedantic,
	 * since I don't think we will see a cwnd this large. :) */
	tp->snd_cwnd_clamp = min_t(u32, tp->snd_cwnd_clamp, 0xffffffff/128);
}

static void hstcp_cong_avoid(struct sock *sk, u32 adk, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct hstcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_slow_start(tp);
	else {
		/* Update AIMD parameters.
		 *
		 * We want to guarantee that:
		 *     hstcp_aimd_vals[ca->ai-1].cwnd <
		 *     snd_cwnd <=
		 *     hstcp_aimd_vals[ca->ai].cwnd
		 */
        /* 在hstcp_admd_vals[]中找到满足条件的ai值 */
		if (tp->snd_cwnd > hstcp_aimd_vals[ca->ai].cwnd) {
			while (tp->snd_cwnd > hstcp_aimd_vals[ca->ai].cwnd &&
			       ca->ai < HSTCP_AIMD_MAX - 1)
				ca->ai++;
		} else if (ca->ai && tp->snd_cwnd <= hstcp_aimd_vals[ca->ai-1].cwnd) {
            /* 很明显，当cwnd小于hstcp_aimd_vals[0](即38)的时候，ai会减为0
             * 上面注释中其实默认了另一条原则：假设hstcp_aimd_vals[-1]对应的cwnd值为0 */
			while (ca->ai && tp->snd_cwnd <= hstcp_aimd_vals[ca->ai-1].cwnd)
				ca->ai--;
		}

		/* Do additive increase */
		if (tp->snd_cwnd < tp->snd_cwnd_clamp) {
			/* cwnd = cwnd + a(w) / cwnd */
            /* 通过这样累加，从一个RTT来看，cwnd就会增加(ca->ai+1)个单位
             * 当cwnd < 38, 即ai会等于零的时候，cwnd的增长就跟reno一样了 */
			tp->snd_cwnd_cnt += ca->ai + 1;
			if (tp->snd_cwnd_cnt >= tp->snd_cwnd) {
				tp->snd_cwnd_cnt -= tp->snd_cwnd;
				tp->snd_cwnd++;
			}
		}
	}
}

static u32 hstcp_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct hstcp *ca = inet_csk_ca(sk);

	/* Do multiplicative decrease */
    /* ssthesh设为 (1 - hstcp_aimd_vals[ai]) * cwnd */
	return max(tp->snd_cwnd - ((tp->snd_cwnd * hstcp_aimd_vals[ca->ai].md) >> 8), 2U);
}


static struct tcp_congestion_ops tcp_highspeed __read_mostly = {
	.init		= hstcp_init,
	.ssthresh	= hstcp_ssthresh,
	.cong_avoid	= hstcp_cong_avoid,
	.min_cwnd	= tcp_reno_min_cwnd,

	.owner		= THIS_MODULE,
	.name		= "highspeed"
};

static int __init hstcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct hstcp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_highspeed);
}

static void __exit hstcp_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_highspeed);
}

module_init(hstcp_register);
module_exit(hstcp_unregister);

MODULE_AUTHOR("John Heffner");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("High Speed TCP");
