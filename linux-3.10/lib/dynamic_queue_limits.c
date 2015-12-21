/*
 * Dynamic byte queue limits.  See include/linux/dynamic_queue_limits.h
 *
 * Copyright (c) 2011, Tom Herbert <therbert@google.com>
 */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/dynamic_queue_limits.h>

#define POSDIFF(A, B) ((int)((A) - (B)) > 0 ? (A) - (B) : 0)
#define AFTER_EQ(A, B) ((int)((A) - (B)) >= 0)

/* Records completed count and recalculates the queue limit */
/* TODO: sent与completed的区别？ */
void dql_completed(struct dql *dql, unsigned int count)
{
	unsigned int inprogress, prev_inprogress, limit;
	unsigned int ovlimit, completed, num_queued;
	bool all_prev_completed;

	num_queued = ACCESS_ONCE(dql->num_queued);

	/* Can't complete more than what's in queue */
	BUG_ON(count > num_queued - dql->num_completed);

	completed = dql->num_completed + count;
	limit = dql->limit;
	ovlimit = POSDIFF(num_queued - dql->num_completed, limit);
	inprogress = num_queued - completed;
	prev_inprogress = dql->prev_num_queued - dql->num_completed;
	all_prev_completed = AFTER_EQ(completed, dql->prev_num_queued);

	if ((ovlimit && !inprogress) ||
	    (dql->prev_ovlimit && all_prev_completed)) {
		/*
		 * Queue considered starved if:
		 *   - The queue was over-limit in the last interval,
		 *     and there is no more data in the queue.
		 *  OR
		 *   - The queue was over-limit in the previous interval and
		 *     when enqueuing it was possible that all queued data
		 *     had been consumed.  This covers the case when queue
		 *     may have becomes starved between completion processing
		 *     running and next time enqueue was scheduled.
		 *
		 *     When queue is starved increase the limit by the amount
		 *     of bytes both sent and completed in the last interval,
		 *     plus any previous over-limit.
		 */
        /* 如果limit在上一个周期达到过，并且queue中已经没有数据了，说明queue limit比较小，需要增大
         * 增大多少：
         *      a. 增加在上一个周期sent和completed的数量 
         *      b. 增加上一个周期over limit的部分 (由于limit不够大，才会over的)
         */
		limit += POSDIFF(completed, dql->prev_num_queued) +
		     dql->prev_ovlimit;
		dql->slack_start_time = jiffies;
		dql->lowest_slack = UINT_MAX;
	} else if (inprogress && prev_inprogress && !all_prev_completed) {
		/*
		 * Queue was not starved, check if the limit can be decreased.
		 * A decrease is only considered if the queue has been busy in
		 * the whole interval (the check above).
		 *
		 * If there is slack, the amount of execess data queued above
		 * the the amount needed to prevent starvation, the queue limit
		 * can be decreased.  To avoid hysteresis we consider the
		 * minimum amount of slack found over several iterations of the
		 * completion routine.
		 */
		unsigned int slack, slack_last_objs;

		/*
		 * Slack is the maximum of
		 *   - The queue limit plus previous over-limit minus twice
		 *     the number of objects completed.  Note that two times
		 *     number of completed bytes is a basis for an upper bound
		 *     of the limit.
		 *   - Portion of objects in the last queuing operation that
		 *     was not part of non-zero previous over-limit.  That is
		 *     "round down" by non-overlimit portion of the last
		 *     queueing operation.
		 */
        /* 如果上一个周期limit保证了数据一直有数据发送，并且limit也没有被达到过，那么就可以考虑降低limit
         * 降多少？*/
		slack = POSDIFF(limit + dql->prev_ovlimit,
		    2 * (completed - dql->num_completed));
		slack_last_objs = dql->prev_ovlimit ?
		    POSDIFF(dql->prev_last_obj_cnt, dql->prev_ovlimit) : 0;

		slack = max(slack, slack_last_objs);

		if (slack < dql->lowest_slack)
			dql->lowest_slack = slack;

        /* 只有超过hold_time后，才会选择降低limit */
        /* slack_start_time记录的是limit上一次"变化"的时刻，至少得让它生效一段时间吧 */
        /* 很奇怪的一个问题：为什么time_after在这里？ 不应该放到进这个if-else分支的地方吗？要不然计算了半天又不用
         * 看着好像是要统计一个周期内的最小的slack值，才这么做的，好吧 */
		if (time_after(jiffies,
			       dql->slack_start_time + dql->slack_hold_time)) {
			limit = POSDIFF(limit, dql->lowest_slack);
			dql->slack_start_time = jiffies;
			dql->lowest_slack = UINT_MAX;
		}
	}

	/* Enforce bounds on limit */
	limit = clamp(limit, dql->min_limit, dql->max_limit);

	if (limit != dql->limit) {
		dql->limit = limit;
		ovlimit = 0;
	}

	dql->adj_limit = limit + completed;
	dql->prev_ovlimit = ovlimit;
	dql->prev_last_obj_cnt = dql->last_obj_cnt;
	dql->num_completed = completed;
	dql->prev_num_queued = num_queued;
}
EXPORT_SYMBOL(dql_completed);

/* 重置DQL：清零计数器 */
void dql_reset(struct dql *dql)
{
	/* Reset all dynamic values */
	dql->limit = 0;
	dql->num_queued = 0;
	dql->num_completed = 0;
	dql->last_obj_cnt = 0;
	dql->prev_num_queued = 0;
	dql->prev_last_obj_cnt = 0;
	dql->prev_ovlimit = 0;
	dql->lowest_slack = UINT_MAX;
	dql->slack_start_time = jiffies;
}
EXPORT_SYMBOL(dql_reset);

/* 初始化DQL queue  */
int dql_init(struct dql *dql, unsigned hold_time)
{
	dql->max_limit = DQL_MAX_LIMIT;
	dql->min_limit = 0;
	dql->slack_hold_time = hold_time;
	dql_reset(dql);
	return 0;
}
EXPORT_SYMBOL(dql_init);
