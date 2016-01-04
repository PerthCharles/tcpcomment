/*
 * nstat.c	handy utility to read counters /proc/net/netstat and snmp
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <fnmatch.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <math.h>

#include <SNAPSHOT.h>   /* iproute2的版本信息 */

int dump_zeros = 0;
int reset_history = 0;
int ignore_history = 0;
int no_output = 0;
int no_update = 0;
int scan_interval = 0;
int time_constant = 0;
double W;
char **patterns;
int npatterns;

char info_source[128];
int source_mismatch;

/* 打开proc接口的通用函数, 主要是处理一下环境变量 */
static int generic_proc_open(const char *env, char *name)
{
	char store[128];
	char *p = getenv(env);
	if (!p) {
		p = getenv("PROC_ROOT") ? : "/proc";
		snprintf(store, sizeof(store)-1, "%s/%s", p, name);
		p = store;
	}
	return open(p, O_RDONLY);
}

int net_netstat_open(void)
{
	return generic_proc_open("PROC_NET_NETSTAT", "net/netstat");
}

int net_snmp_open(void)
{
	return generic_proc_open("PROC_NET_SNMP", "net/snmp");
}

int net_snmp6_open(void)
{
	return generic_proc_open("PROC_NET_SNMP6", "net/snmp6");
}

/* nstat中采用单链表的形式存储各个counter */
struct nstat_ent
{
	struct nstat_ent *next;
	char		 *id;           /* counter的名字 */
	unsigned long long val;     /* counter的值 */
	unsigned long	   ival;
	double		   rate;
};

struct nstat_ent *kern_db;      /* kernel database, 即proc接口获取值的链表 */
struct nstat_ent *hist_db;      /* history database, 即从存储文件中取出来的链表 */

/* 有一些计数器是没有用的，比如它是常量，或者不是递增的counter */
char *useless_numbers[] = {
"IpForwarding", "IpDefaultTTL",
"TcpRtoAlgorithm", "TcpRtoMin", "TcpRtoMax",
"TcpMaxConn", "TcpCurrEstab"
};

/* 根据counter id(名字)，判断它是否是对于nstat没有用的 */
int useless_number(char *id)
{
	int i;
	for (i=0; i<sizeof(useless_numbers)/sizeof(*useless_numbers); i++)
		if (strcmp(id, useless_numbers[i]) == 0)
			return 1;
	return 0;
}

/* 判断counter名字(id)是否匹配某一个pattern */
int match(char *id)
{
	int i;

	if (npatterns == 0)
		return 1;

	for (i=0; i<npatterns; i++) {
        /* id是否与某一个pattern匹配 ? 匹配fnmatch()返回0 */
		if (!fnmatch(patterns[i], id, 0))
			return 1;
	}
	return 0;
}

/* 所谓的good table就是一行一个counter的table, 如nstat的输出、/proc/net/snmp6
 * 函数功能：将fp文件的数据读取到kern_db链表中
 */
void load_good_table(FILE *fp)
{
	char buf[4096];
	struct nstat_ent *db = NULL;
	struct nstat_ent *n;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		int nr;
		unsigned long long val;
		double rate;
		char idbuf[sizeof(buf)];
        /* nstat第一行的输出是表明数据的来源，以"#"开始。一般都是来自kernel */
		if (buf[0] == '#') {
            /* TODO-DONE: 为什么要将最后一个字符改成结束标记符? 
             * 答: 将'\n'替换成'\n' fgets会将'\n'也读进来 ! */
			buf[strlen(buf)-1] = 0;     
            /* 如果读取的数据，与确定好的数据来源不一致，标记为source mismatch */
			if (info_source[0] && strcmp(info_source, buf+1))
				source_mismatch = 1;
            /* 更新 info source, info_source本身不带'#' */
			info_source[0] = 0;
			strncat(info_source, buf+1, sizeof(info_source)-1);
			continue;
		}
		/* idbuf is as big as buf, so this is safe */
        /* 读入一个计数器的值 */
		nr = sscanf(buf, "%s%llu%lg", idbuf, &val, &rate);
		if (nr < 2)
			abort();
		if (nr < 3)     /* 由于该函数被复用去读/proc/net/snmp6的计数器，因此存在nr=2的情况 */
			rate = 0;
		if (useless_number(idbuf))
			continue;
		if ((n = malloc(sizeof(*n))) == NULL)
			abort();
		n->id = strdup(idbuf);  /* 复制一份新的string给链表中的id */
		n->ival = (unsigned long)val;
		n->val = val;   /* good table就存到了val中 */
		n->rate = rate;
		n->next = db;
		db = n;
	}
    /* 上一个while执行后的结果：
     *  db指向datebase单链表的表头 */

    /* 将db指向的单链表拼接到kern_db链表中 */
	while (db) {
		n = db;
		db = db->next;
		n->next = kern_db;
		kern_db = n;
	}
}


/* 所谓的ugly table就是一行是counter名称，接着一行是counter值的table, 如/proc/net/netstat
 * 函数功能：将fp文件的数据读取到kern_db链表中
 */
void load_ugly_table(FILE *fp)
{
	char buf[4096];
	struct nstat_ent *db = NULL;
	struct nstat_ent *n;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char idbuf[sizeof(buf)];
		int  off;
		char *p;

        /* 虽然丑，但是也是有固定格式的，':' 之后才是计数器相关内容 */
		p = strchr(buf, ':');
		if (!p)
			abort();
		*p = 0;
        /* 使用idbuf存储内容：行首标记字段 + counter的id，即名字 */
		idbuf[0] = 0;
		strncat(idbuf, buf, sizeof(idbuf) - 1);
		off = p - buf;  /* 行首标记字段的长度，如Tcp */
		p += 2;     /* 将p指向第一个counter id开始的位置 */

		while (*p) {
            /* next指向下一个计数器id的开始位置 */
			char *next;
			if ((next = strchr(p, ' ')) != NULL)
				*next++ = 0;
			else if ((next = strchr(p, '\n')) != NULL)
				*next++ = 0;

            /* 将counter id拼接到idbuf中 */
			if (off < sizeof(idbuf)) {
				idbuf[off] = 0;
				strncat(idbuf, p, sizeof(idbuf) - off - 1);
			}
			n = malloc(sizeof(*n));
			if (!n)
				abort();
			n->id = strdup(idbuf);
			n->rate = 0;
			n->next = db;
			db = n;
			p = next;
		}
		n = db;
        /* 至此，n和db都指向一个未复制的nstat_ent list的表头 */
		if (fgets(buf, sizeof(buf), fp) == NULL)
			abort();

        /* 开始解析counter value */
		do {
			p = strrchr(buf, ' ');
			if (!p)
				abort();
			*p = 0;
            /* 读的时候，只用ival存，即最长也就是个unsinged long */
			if (sscanf(p+1, "%lu", &n->ival) != 1)
				abort();
			n->val = n->ival;
			/* Trick to skip "dummy" trailing ICMP MIB in 2.4 */
			if (strcmp(idbuf, "IcmpOutAddrMaskReps") == 0)
				idbuf[5] = 0;
			else
				n = n->next;
        /* TODO： 这个判断条件是什么意思 ? */
		} while (p > buf + off + 2);
	}

	while (db) {
		n = db;
		db = db->next;
		if (useless_number(n->id)) {
			free(n->id);
			free(n);
		} else {
			n->next = kern_db;
			kern_db = n;
		}
	}
}

void load_snmp(void)
{
	FILE *fp = fdopen(net_snmp_open(), "r");
	if (fp) {
		load_ugly_table(fp);
		fclose(fp);
	}
}

void load_snmp6(void)
{
	FILE *fp = fdopen(net_snmp6_open(), "r");
	if (fp) {
		load_good_table(fp);
		fclose(fp);
	}
}

void load_netstat(void)
{
	FILE *fp = fdopen(net_netstat_open(), "r");
	if (fp) {
		load_ugly_table(fp);
		fclose(fp);
	}
}

void dump_kern_db(FILE *fp, int to_hist)
{
	struct nstat_ent *n, *h;
	h = hist_db;
	fprintf(fp, "#%s\n", info_source);
	for (n=kern_db; n; n=n->next) {
		unsigned long long val = n->val;
		if (!dump_zeros && !val && !n->rate)
			continue;
		if (!match(n->id)) {
			struct nstat_ent *h1;
			if (!to_hist)
				continue;
			for (h1 = h; h1; h1 = h1->next) {
				if (strcmp(h1->id, n->id) == 0) {
					val = h1->val;
					h = h1->next;
					break;
				}
			}
		}
		fprintf(fp, "%-32s%-16llu%6.1f\n", n->id, val, n->rate);
	}
}

void dump_incr_db(FILE *fp)
{
	struct nstat_ent *n, *h;
	h = hist_db;
	fprintf(fp, "#%s\n", info_source);
	for (n=kern_db; n; n=n->next) {
		int ovfl = 0;
		unsigned long long val = n->val;
		struct nstat_ent *h1;
		for (h1 = h; h1; h1 = h1->next) {
			if (strcmp(h1->id, n->id) == 0) {
				if (val < h1->val) {
					ovfl = 1;
					val = h1->val;
				}
				val -= h1->val;
				h = h1->next;
				break;
			}
		}
		if (!dump_zeros && !val && !n->rate)
			continue;
		if (!match(n->id))
			continue;
		fprintf(fp, "%-32s%-16llu%6.1f%s\n", n->id, val,
			n->rate, ovfl?" (overflow)":"");
	}
}

static int children;

void sigchild(int signo)
{
}

void update_db(int interval)
{
	struct nstat_ent *n, *h;

	n = kern_db;
	kern_db = NULL;

	load_netstat();
	load_snmp6();
	load_snmp();

	h = kern_db;
	kern_db = n;

	for (n = kern_db; n; n = n->next) {
		struct nstat_ent *h1;
		for (h1 = h; h1; h1 = h1->next) {
			if (strcmp(h1->id, n->id) == 0) {
				double sample;
				unsigned long incr = h1->ival - n->ival;
				n->val += incr;
				n->ival = h1->ival;
				sample = (double)(incr*1000)/interval;
				if (interval >= scan_interval) {
					n->rate += W*(sample-n->rate);
				} else if (interval >= 1000) {
					if (interval >= time_constant) {
						n->rate = sample;
					} else {
						double w = W*(double)interval/scan_interval;
						n->rate += w*(sample-n->rate);
					}
				}

				while (h != h1) {
					struct nstat_ent *tmp = h;
					h = h->next;
					free(tmp->id);
					free(tmp);
				};
				h = h1->next;
				free(h1->id);
				free(h1);
				break;
			}
		}
	}
}

#define T_DIFF(a,b) (((a).tv_sec-(b).tv_sec)*1000 + ((a).tv_usec-(b).tv_usec)/1000)


void server_loop(int fd)
{
	struct timeval snaptime = { 0 };
	struct pollfd p;
	p.fd = fd;
	p.events = p.revents = POLLIN;

    /* 如果以deamon形式运行nstat, 则source就不是简单的kernel了
     * 即使在64位机器上，%d最多会占用19位，unsinged long最多能占用20位
     * 从而一下的format最大长度为： 19*3 + 20 + 32 = 109 在加上'\0' 最多也就110位，不会溢出 */
	sprintf(info_source, "%d.%lu sampling_interval=%d time_const=%d",
		getpid(), (unsigned long)random(), scan_interval/1000, time_constant/1000);

	load_netstat();
	load_snmp6();
	load_snmp();

	for (;;) {
		int status;
		int tdiff;
		struct timeval now;
		gettimeofday(&now, NULL);
		tdiff = T_DIFF(now, snaptime);
		if (tdiff >= scan_interval) {
			update_db(tdiff);
			snaptime = now;
			tdiff = 0;
		}
		if (poll(&p, 1, tdiff + scan_interval) > 0
		    && (p.revents&POLLIN)) {
			int clnt = accept(fd, NULL, NULL);
			if (clnt >= 0) {
				pid_t pid;
				if (children >= 5) {
					close(clnt);
				} else if ((pid = fork()) != 0) {
					if (pid>0)
						children++;
					close(clnt);
				} else {
					FILE *fp = fdopen(clnt, "w");
					if (fp) {
						if (tdiff > 0)
							update_db(tdiff);
						dump_kern_db(fp, 0);
					}
					exit(0);
				}
			}
		}
		while (children && waitpid(-1, &status, WNOHANG) > 0)
			children--;
	}
}

int verify_forging(int fd)
{
	struct ucred cred;
	socklen_t olen = sizeof(cred);

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, (void*)&cred, &olen) ||
	    olen < sizeof(cred))
		return -1;
	if (cred.uid == getuid() || cred.uid == 0)
		return 0;
	return -1;
}

static void usage(void) __attribute__((noreturn));

static void usage(void)
{
	fprintf(stderr,
"Usage: nstat [ -h?vVzrnasd:t: ] [ PATTERN [ PATTERN ] ]\n"
		);
	exit(-1);
}


int main(int argc, char *argv[])
{
	char *hist_name;
	struct sockaddr_un sun;
	FILE *hist_fp = NULL;
	int ch;
	int fd;

	while ((ch = getopt(argc, argv, "h?vVzrnasd:t:")) != EOF) {
		switch(ch) {
		case 'z':
			dump_zeros = 1;
			break;
		case 'r':
			reset_history = 1;
			break;
		case 'a':
			ignore_history = 1;
			break;
		case 's':
			no_update = 1;
			break;
		case 'n':
			no_output = 1;
			break;
		case 'd':
			scan_interval = 1000*atoi(optarg);
			break;
		case 't':
			if (sscanf(optarg, "%d", &time_constant) != 1 ||
			    time_constant <= 0) {
				fprintf(stderr, "nstat: invalid time constant divisor\n");
				exit(-1);
			}
			break;
		case 'v':
		case 'V':
			printf("nstat utility, iproute2-ss%s\n", SNAPSHOT);
			exit(0);
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	sun.sun_family = AF_UNIX;
	sun.sun_path[0] = 0;
	sprintf(sun.sun_path+1, "nstat%d", getuid());

	if (scan_interval > 0) {
		if (time_constant == 0)
			time_constant = 60;
		time_constant *= 1000;
		W = 1 - 1/exp(log(10)*(double)scan_interval/time_constant);
		if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
			perror("nstat: socket");
			exit(-1);
		}
		if (bind(fd, (struct sockaddr*)&sun, 2+1+strlen(sun.sun_path+1)) < 0) {
			perror("nstat: bind");
			exit(-1);
		}
		if (listen(fd, 5) < 0) {
			perror("nstat: listen");
			exit(-1);
		}
		if (daemon(0, 0)) {
			perror("nstat: daemon");
			exit(-1);
		}
		signal(SIGPIPE, SIG_IGN);
		signal(SIGCHLD, sigchild);
		server_loop(fd);
		exit(0);
	}

	patterns = argv;
	npatterns = argc;

	if ((hist_name = getenv("NSTAT_HISTORY")) == NULL) {
		hist_name = malloc(128);
		sprintf(hist_name, "/tmp/.nstat.u%d", getuid());
	}

	if (reset_history)
		unlink(hist_name);

	if (!ignore_history || !no_update) {
		struct stat stb;

		fd = open(hist_name, O_RDWR|O_CREAT|O_NOFOLLOW, 0600);
		if (fd < 0) {
			perror("nstat: open history file");
			exit(-1);
		}
		if ((hist_fp = fdopen(fd, "r+")) == NULL) {
			perror("nstat: fdopen history file");
			exit(-1);
		}
		if (flock(fileno(hist_fp), LOCK_EX)) {
			perror("nstat: flock history file");
			exit(-1);
		}
		if (fstat(fileno(hist_fp), &stb) != 0) {
			perror("nstat: fstat history file");
			exit(-1);
		}
		if (stb.st_nlink != 1 || stb.st_uid != getuid()) {
			fprintf(stderr, "nstat: something is so wrong with history file, that I prefer not to proceed.\n");
			exit(-1);
		}
		if (!ignore_history) {
			FILE *tfp;
			long uptime = -1;
			if ((tfp = fopen("/proc/uptime", "r")) != NULL) {
				if (fscanf(tfp, "%ld", &uptime) != 1)
					uptime = -1;
				fclose(tfp);
			}
			if (uptime >= 0 && time(NULL) >= stb.st_mtime+uptime) {
				fprintf(stderr, "nstat: history is aged out, resetting\n");
				ftruncate(fileno(hist_fp), 0);
			}
		}

		load_good_table(hist_fp);

		hist_db = kern_db;
		kern_db = NULL;
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0 &&
	    (connect(fd, (struct sockaddr*)&sun, 2+1+strlen(sun.sun_path+1)) == 0
	     || (strcpy(sun.sun_path+1, "nstat0"),
		 connect(fd, (struct sockaddr*)&sun, 2+1+strlen(sun.sun_path+1)) == 0))
	    && verify_forging(fd) == 0) {
		FILE *sfp = fdopen(fd, "r");
		load_good_table(sfp);
		if (hist_db && source_mismatch) {
			fprintf(stderr, "nstat: history is stale, ignoring it.\n");
			hist_db = NULL;
		}
		fclose(sfp);
	} else {
		if (fd >= 0)
			close(fd);
		if (hist_db && info_source[0] && strcmp(info_source, "kernel")) {
			fprintf(stderr, "nstat: history is stale, ignoring it.\n");
			hist_db = NULL;
			info_source[0] = 0;
		}
		load_netstat();
		load_snmp6();
		load_snmp();
        /* 默认的info_source是kernel */
		if (info_source[0] == 0)
			strcpy(info_source, "kernel");
	}

	if (!no_output) {
		if (ignore_history || hist_db == NULL)
			dump_kern_db(stdout, 0);
		else
			dump_incr_db(stdout);
	}
	if (!no_update) {
		ftruncate(fileno(hist_fp), 0);
		rewind(hist_fp);
		dump_kern_db(hist_fp, 1);
		fflush(hist_fp);
	}
	exit(0);
}
