#ifndef __NETNS_MIB_H__
#define __NETNS_MIB_H__

#include <net/snmp.h>

/* 这个结构体是隶属于namespace */
struct netns_mib {
    /* 下面每一个定义的item，都是指向相应结构的一个指针
     * 如tcp_statistics是一个指向struct tcp_mib结构体的指针 */
	DEFINE_SNMP_STAT(struct tcp_mib, tcp_statistics);
	DEFINE_SNMP_STAT(struct ipstats_mib, ip_statistics);
	DEFINE_SNMP_STAT(struct linux_mib, net_statistics);
	DEFINE_SNMP_STAT(struct udp_mib, udp_statistics);
	DEFINE_SNMP_STAT(struct udp_mib, udplite_statistics);
	DEFINE_SNMP_STAT(struct icmp_mib, icmp_statistics);
	DEFINE_SNMP_STAT_ATOMIC(struct icmpmsg_mib, icmpmsg_statistics);

#if IS_ENABLED(CONFIG_IPV6)
	struct proc_dir_entry *proc_net_devsnmp6;
	DEFINE_SNMP_STAT(struct udp_mib, udp_stats_in6);
	DEFINE_SNMP_STAT(struct udp_mib, udplite_stats_in6);
	DEFINE_SNMP_STAT(struct ipstats_mib, ipv6_statistics);
	DEFINE_SNMP_STAT(struct icmpv6_mib, icmpv6_statistics);
	DEFINE_SNMP_STAT_ATOMIC(struct icmpv6msg_mib, icmpv6msg_statistics);
#endif
#ifdef CONFIG_XFRM_STATISTICS
	DEFINE_SNMP_STAT(struct linux_xfrm_mib, xfrm_statistics);
#endif
};

#endif
