/*
 * NET		Generic infrastructure for Network protocols.
 *
 *		Definitions for request_sock 
 *
 * Authors:	Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *
 * 		From code originally in include/net/tcp.h
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _REQUEST_SOCK_H
#define _REQUEST_SOCK_H

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/bug.h>

#include <net/sock.h>

struct request_sock;
struct sk_buff;
struct dst_entry;
struct proto;

struct request_sock_ops {
	int		family;
	int		obj_size;
	struct kmem_cache	*slab;
	char		*slab_name;
    /* 负责重传syn/ack包 */
	int		(*rtx_syn_ack)(struct sock *sk,
				       struct request_sock *req);
    /* 负责发送ack包 */
	void		(*send_ack)(struct sock *sk, struct sk_buff *skb,
				    struct request_sock *req);
    /* 负责发送reset包 */
	void		(*send_reset)(struct sock *sk,
				      struct sk_buff *skb);
	void		(*destructor)(struct request_sock *req);
    /* 重传syn/ack的timer */
	void		(*syn_ack_timeout)(struct sock *sk,
					   struct request_sock *req);
};

extern int inet_rtx_syn_ack(struct sock *parent, struct request_sock *req);

/* struct request_sock - mini sock to represent a connection request
 */
/* 为了性能考虑(防syn flooding攻击), 仅收到一个syn包不会创建一个庞大的tcp_sock结构体，
 * 而是创建request_sock结构体临时代替用着. 只有在完成三次握手后，才会真的创建tcp_sock结构体 */
struct request_sock {
	struct request_sock		*dl_next;   /* 指向synq collisin hash table的下一个reqsk */
	u16				mss;
    /* num_retrans 略大于num_timeout，因为在收到client重传的syn包时，timeout不会增加，retrans会增加 */
	u8				num_retrans; /* number of retransmits, 即syn/ack重传的次数 */
	u8				cookie_ts:1; /* syncookie: encode tcpopts in timestamp */
	u8				num_timeout:7; /* number of timeouts, 即syn/ack timer超时的次数 */
	/* The following two fields can be easily recomputed I think -AK */
	u32				window_clamp; /* window clamp at creation time */
	u32				rcv_wnd;	  /* rcv_wnd offered first time */
	u32				ts_recent;      /* 最近收到的一个SYN包中带着的timestamp值，如果有的话 */
	unsigned long			expires;    /* 用于重传syn/ack的timer值 */
	const struct request_sock_ops	*rsk_ops;
    /* 指向为新连接建立的sk结构体，在syn queue中sk=NULL, 在accept queue中才有效 */
	struct sock			*sk;    
	u32				secid;
	u32				peer_secid;
};

/* 分配一个request_sock结构体，分配不成功则返回NULL */
static inline struct request_sock *reqsk_alloc(const struct request_sock_ops *ops)
{
	struct request_sock *req = kmem_cache_alloc(ops->slab, GFP_ATOMIC);

    /* 设置request socket的相关处理函数 */
	if (req != NULL)
		req->rsk_ops = ops;

	return req;
}

static inline void __reqsk_free(struct request_sock *req)
{
	kmem_cache_free(req->rsk_ops->slab, req);
}

/* 删除一个request_sock */
static inline void reqsk_free(struct request_sock *req)
{
	req->rsk_ops->destructor(req);
	__reqsk_free(req);
}

extern int sysctl_max_syn_backlog;

/** struct listen_sock - listen state
 *
 * @max_qlen_log - log_2 of maximal queued SYNs/REQUESTs
 */
struct listen_sock {
	u8			max_qlen_log;       /* log_2 of maximal queued SYNs */
	u8			synflood_warned;    /* 标记是否打印了synflood warning */
	/* 2 bytes hole, try to use */
    /* 书中有如下一段描述，等具体看qlen qlen_young的代码时好好理解
     * Basically, the policy is to still drop any new connection request based on the young
     * connection requests in the following case:
     *     a. SYN queue can accommodate more open connection requests in the SYN queue (tcp_synq_is_full() == 0), *AND*
     *     b. Accept queue is full (tcp_acceptq_is_full() != 0) and SYN queue still contains more than one young
     *        connection request (tcp_synq_young() > 1) 
     */
	int			qlen;               /* 记录syn queue中的connection request个数 */
	int			qlen_young;         /* 记录syn queue中，未重传syn/ack包的connection request个数 */
	int			clock_hand;         /* 记录syn queue timer每次超时后，从哪个地方开始接着处理 */
	u32			hash_rnd;
	u32			nr_table_entries;
    /* syn queue的hash table， 每一个entries就是一个request_sock的hash冲突链
     * hash因子是：client port + client ip */
	struct request_sock	*syn_table[0];
};

/*
 * For a TCP Fast Open listener -
 *	lock - protects the access to all the reqsk, which is co-owned by
 *		the listener and the child socket.
 *	qlen - pending TFO requests (still in TCP_SYN_RECV).
 *	max_qlen - max TFO reqs allowed before TFO is disabled.
 *
 *	XXX (TFO) - ideally these fields can be made as part of "listen_sock"
 *	structure above. But there is some implementation difficulty due to
 *	listen_sock being part of request_sock_queue hence will be freed when
 *	a listener is stopped. But TFO related fields may continue to be
 *	accessed even after a listener is closed, until its sk_refcnt drops
 *	to 0 implying no more outstanding TFO reqs. One solution is to keep
 *	listen_opt around until	sk_refcnt drops to 0. But there is some other
 *	complexity that needs to be resolved. E.g., a listener can be disabled
 *	temporarily through shutdown()->tcp_disconnect(), and re-enabled later.
 */
struct fastopen_queue {
	struct request_sock	*rskq_rst_head; /* Keep track of past TFO */
	struct request_sock	*rskq_rst_tail; /* requests that caused RST.
						 * This is part of the defense
						 * against spoofing attack.
						 */
	spinlock_t	lock;
	int		qlen;		/* # of pending (TCP_SYN_RECV) reqs */
	int		max_qlen;	/* != 0 iff TFO is currently enabled */
};

/** struct request_sock_queue - queue of request_socks
 *
 * @rskq_accept_head - FIFO head of established children
 * @rskq_accept_tail - FIFO tail of established children
 * @rskq_defer_accept - User waits for some data after accept()
 * @syn_wait_lock - serializer
 *
 * %syn_wait_lock is necessary only to avoid proc interface having to grab the main
 * lock sock while browsing the listening hash (otherwise it's deadlock prone).
 *
 * This lock is acquired in read mode only from listening_get_next() seq_file
 * op and it's acquired in write mode _only_ from code that is actively
 * changing rskq_accept_head. All readers that are holding the master sock lock
 * don't need to grab this lock in read mode too as rskq_accept_head. writes
 * are always protected from the main sock lock.
 */
struct request_sock_queue {
    /* 只要放到accept queue中的reqsk，它的sk域不为空。
     * 此时TCP连接其实已经建立了，client完全是可以发送数据给这个sk的 */
	struct request_sock	*rskq_accept_head;
	struct request_sock	*rskq_accept_tail;
	rwlock_t		syn_wait_lock;
    /* 如果用户配置了该值，则在收到三次握手的最后一个ACK后，如果ACK不带数据，则丢弃该ACK包
     * 也就不会直接accept，而是等待带有数据的ACK到来才会accept。
     * rskq_defer_accept指定defer accept的最长时间（实际使用时会转换成syn/ack的重传次数,因为这个timer是复用了
     * syn/ack的timer), 超过指定时间还没有收到对端发送过来数据，则socket会被删除 */
	u8			rskq_defer_accept;  
	/* 3 bytes hole, try to pack */
    /* 这就是半连接队列，即受到了第一个SYN，还没完成3WHS的request sock */
	struct listen_sock	*listen_opt;    
	struct fastopen_queue	*fastopenq; /* This is non-NULL iff TFO has been
					     * enabled on this listener. Check
					     * max_qlen != 0 in fastopen_queue
					     * to determine if TFO is enabled
					     * right at this moment.
					     */
};

extern int reqsk_queue_alloc(struct request_sock_queue *queue,
			     unsigned int nr_table_entries);

extern void __reqsk_queue_destroy(struct request_sock_queue *queue);
extern void reqsk_queue_destroy(struct request_sock_queue *queue);
extern void reqsk_fastopen_remove(struct sock *sk,
				  struct request_sock *req, bool reset);

static inline struct request_sock *
	reqsk_queue_yank_acceptq(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	queue->rskq_accept_head = NULL;
	return req;
}

/* 判断accept queue是否为空 */
static inline int reqsk_queue_empty(struct request_sock_queue *queue)
{
	return queue->rskq_accept_head == NULL;
}

/* 将req从队列中移除 */
static inline void reqsk_queue_unlink(struct request_sock_queue *queue,
				      struct request_sock *req,
				      struct request_sock **prev_req)
{
	write_lock(&queue->syn_wait_lock);
	*prev_req = req->dl_next;
	write_unlock(&queue->syn_wait_lock);
}

static inline void reqsk_queue_add(struct request_sock_queue *queue,
				   struct request_sock *req,
				   struct sock *parent,
				   struct sock *child)
{
    /* 将新创建的sk挂载到req中 */
	req->sk = child;
	sk_acceptq_added(parent);   /* parent是处于listen状态的socket，增加它的accept queue的计数器 */

    /* 将req加入到accept queue中 */
	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_head = req;
	else
		queue->rskq_accept_tail->dl_next = req;

	queue->rskq_accept_tail = req;
	req->dl_next = NULL;
}

/* 将req从accept queue中移除, 并返回第一个req */
static inline struct request_sock *reqsk_queue_remove(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	WARN_ON(req == NULL);

	queue->rskq_accept_head = req->dl_next;
	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_tail = NULL;

	return req;
}

/* 将req从syn queue移除后，更新计数器 queue len */
static inline int reqsk_queue_removed(struct request_sock_queue *queue,
				      struct request_sock *req)
{
	struct listen_sock *lopt = queue->listen_opt;

    /* 如果没有重传过syn/ack，则是young req */
	if (req->num_timeout == 0)
		--lopt->qlen_young;

	return --lopt->qlen;
}

/* 将req加入syn queue后，更新计数器 queue len */
static inline int reqsk_queue_added(struct request_sock_queue *queue)
{
	struct listen_sock *lopt = queue->listen_opt;
	const int prev_qlen = lopt->qlen;

	lopt->qlen_young++;
	lopt->qlen++;
	return prev_qlen;
}

/* 返回syn queue的长度 */
static inline int reqsk_queue_len(const struct request_sock_queue *queue)
{
	return queue->listen_opt != NULL ? queue->listen_opt->qlen : 0;
}

/* 返回syn queue中没有重传syn/ack包的req个数 */
static inline int reqsk_queue_len_young(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen_young;
}

/* 判断syn queue是否已经满了 */
static inline int reqsk_queue_is_full(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen >> queue->listen_opt->max_qlen_log;
}

/* 将req加入到syn queue中对应的collision hash list中 */
static inline void reqsk_queue_hash_req(struct request_sock_queue *queue,
					u32 hash, struct request_sock *req,
					unsigned long timeout)
{
	struct listen_sock *lopt = queue->listen_opt;

	req->expires = jiffies + timeout;
	req->num_retrans = 0;
	req->num_timeout = 0;
	req->sk = NULL;
	req->dl_next = lopt->syn_table[hash];

	write_lock(&queue->syn_wait_lock);
	lopt->syn_table[hash] = req;
	write_unlock(&queue->syn_wait_lock);
}

#endif /* _REQUEST_SOCK_H */
