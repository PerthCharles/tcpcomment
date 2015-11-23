/* Tom Kelly's Scalable TCP
 *
 * See http://www.deneholme.net/tom/scalable/
 *
 * John Heffner <jheffner@sc.edu>
 */

#include <linux/module.h>
#include <net/tcp.h>

/* These factors derived from the recommended values in the aer:
 * .01 and and 7/8. We use 50 instead of 100 to account for
 * delayed ack.
 */
#define TCP_SCALABLE_AI_CNT	50U
#define TCP_SCALABLE_MD_SCALE	3

static void tcp_scalable_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_slow_start(tp);
	else
        /* scalable算法核心1 */
        /* 如果cwnd < 50, 则使用Reno一样的策略增长cwnd
         * 主要是限制cwnd较大时的AI值为一个常数：50
         * 因此如果这种情况下要恢复到进入快速重传时的cwnd值，比如从reduced增长回original，
         * 那么需要的恢复时间就是(original - reduced)/50个RTT，而reduced = 7/8 * original
         * 故恢复时间为original/(50 * 8)个RTT */
		tcp_cong_avoid_ai(tp, min(tp->snd_cwnd, TCP_SCALABLE_AI_CNT));
}

static u32 tcp_scalable_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
    /* scalable算法核心2 */
    /* 慢启动阈值设置为7/8*cwnd */
	return max(tp->snd_cwnd - (tp->snd_cwnd>>TCP_SCALABLE_MD_SCALE), 2U);
}


static struct tcp_congestion_ops tcp_scalable __read_mostly = {
	.ssthresh	= tcp_scalable_ssthresh,
	.cong_avoid	= tcp_scalable_cong_avoid,
	.min_cwnd	= tcp_reno_min_cwnd,

	.owner		= THIS_MODULE,
	.name		= "scalable",
};

static int __init tcp_scalable_register(void)
{
	return tcp_register_congestion_control(&tcp_scalable);
}

static void __exit tcp_scalable_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_scalable);
}

module_init(tcp_scalable_register);
module_exit(tcp_scalable_unregister);

MODULE_AUTHOR("John Heffner");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Scalable TCP");
