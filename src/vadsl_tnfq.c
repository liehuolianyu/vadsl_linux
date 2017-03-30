// vadsl_tnfq: 虚拟ADSL: 多线程路由过滤进程

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>															//Thread
#include <signal.h>																//Signal
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>															//For struct in_addr
#include <linux/ip.h>
#include <linux/netfilter.h>													//For NF_ACCEPT
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "vadsl_common.h"

#define LOG_PATH "/var/log/vadsl"												//守护进程模式时默认日志文件

#define THREAD_RETRY_TIMES	5
#define TIME_TO_WAIT	2														//s
#define TIME_THREAD_CH	200														//us

#define SIZE_ETHER_MTU	1500
#define SIZE_HEADER_IP	20
#define SIZE_HEADER_GRE	4
#define SIZE_IP_STR	16
#define SIZE_MSG	100

char *p_name="vadsl_nfq";														//程序名
struct thread_info{
	pthread_t thread_id;
	int thread_num;
	bool thread_do_exit;
	bool thread_succ;
	int thread_fail_num;
	int thread_packets;
	struct nfq_q_handle *thread_nfq_qh;
};
struct nfq_cb_info{
	int thread_num;
	char *pktbuf;
	char *pktbuf_rip;
	char *message;
};
bool running=true,nfq_h_opened=false;
struct nfq_handle *nfq_h;
char message[SIZE_MSG+1]={0};
struct thread_info *tinfo=NULL;													//make sure that free(thread_info) always success
int num_threads = 1;
pthread_mutex_t print_mutex;

char *bindip=NULL,*relayip=NULL;
const char greheader[] = {0x00, 0x00, 0x08, 0x00};

static void nfq_h_close(){
	nfq_unbind_pf(nfq_h, AF_INET);
	nfq_close(nfq_h);
}

static void exit_on_error(){
	free(tinfo);
	if(nfq_h_opened)
		nfq_h_close();
	exit(EXIT_FAILURE);
}

void error_print(char *str, bool use_errno){
	pthread_mutex_lock(&print_mutex);
	error_print_nolock(str, use_errno);
	pthread_mutex_unlock(&print_mutex);
}

void info_print(char *str){
	pthread_mutex_lock(&print_mutex);
	info_print_nolock(str);
	pthread_mutex_unlock(&print_mutex);
}

void pth_error_exit(char * str, int err_num){									//Need to modify
	snprintf(message,SIZE_MSG, "%s: %s", str, strerror(err_num));
	error_print(message, false);
	running = false;
	exit_on_error();
}

static void nfq_h_open(){
	nfq_h = nfq_open();
	if (!nfq_h) {
		error_print("nfq_open()", true);
		exit_on_error();
	}else{
		nfq_h_opened = true;
	}
	if (nfq_unbind_pf(nfq_h, AF_INET) < 0) {
		error_print("nfq_unbind_pf()", true);
		exit_on_error();
	}
	if (nfq_bind_pf(nfq_h, AF_INET) < 0) {
		error_print("nfq_bind_pf()", true);
		exit_on_error();
	}
}

void print_mutex_init(){
	int res=pthread_mutex_init(&print_mutex, NULL);
	if(res != 0)
		pth_error_exit("pthread_mutex_init()",res);
}

static void sig_handler_exit(int sig){
	int res;

	snprintf(message, SIZE_MSG, "Signal %d Received", sig);
	info_print(message);

	switch(sig){
		case SIGINT:
		case SIGTERM:
		case SIGQUIT:
			running = false;
		case SIGUSR1:
			if(tinfo)
				for(int i=0; i<num_threads; i++){
					snprintf(message,SIZE_MSG, "Trying to Cancel Thread %d", tinfo[i].thread_num);
					info_print_nolock(message);
					res = pthread_cancel(tinfo[i].thread_id);
					if(res){
						snprintf(message,SIZE_MSG, "pthread_cancel(): %s", strerror(res));
						error_print_nolock(message, false);
					}
			}
		default:
			break;
	}
}

void sig_handler_register(){
	struct sigaction sigact_exit;

	sigact_exit.sa_handler = sig_handler_exit;									//Build the struct for exit signal handle
	sigemptyset(&sigact_exit.sa_mask);
	sigact_exit.sa_flags = 0;
	sigaction(SIGINT, &sigact_exit, NULL);										//Apply exit signal handle action
	sigaction(SIGQUIT, &sigact_exit, NULL);
	sigaction(SIGTERM, &sigact_exit, NULL);
}

static void usage_print(){
	printf("Usage: -b <bind IP addr> -r <transfer gateway addr> [ -dh ] [ -t thread number ] [ -f log file path ]\n");
	printf("Options:\n");
	printf("\t-b  bind IP addr\n");
	printf("\t-d  run as daemon (default off)\n");
	printf("\t-f  log file path (daemon mode default path is /var/log/vadsl\n");
	printf("\t    or print to stderr. enable to redirect stderr to the log file\n");
	printf("\t-h  print help info\n");
	printf("\t-r  transfer gateway addr\n");
	printf("\t-t  route filter thread number (in range 1-12)\n");
}

unsigned short chksum(unsigned short *buf, int nwords) {
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return (unsigned short) (~sum);
}

static int nfq_mycallback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
	struct nfq_cb_info *ncinfo_this = (struct nfq_cb_info *)data;
	struct nfqnl_msg_packet_hdr *ph;
	int id,plen,pktlen;
	char *pktbuf = ncinfo_this->pktbuf;
	struct iphdr *gipheader = (struct iphdr *)pktbuf;
	char *pktbuf_rip = ncinfo_this->pktbuf_rip;
	struct iphdr *ripheader = (struct iphdr *)pktbuf_rip;
	char *pdata;

	ph = nfq_get_msg_packet_hdr(nfa);
	if(ph)
		id = ntohl(ph->packet_id);
	else{
		error_print("nfq_get_msg_packet_hdr()",true);
		return (EXIT_FAILURE);
	}

	plen = nfq_get_payload(nfa, &pdata);
	if (plen < 0){
		error_print("nfq_get_payload()",true);
		return (EXIT_FAILURE);
	}
	pktlen = SIZE_HEADER_IP + SIZE_HEADER_GRE + plen;
	if(pktlen > SIZE_ETHER_MTU){
		snprintf(ncinfo_this->message,SIZE_MSG,"Packet Size Overload,Deacrease MTU Value");
		error_print(ncinfo_this->message,false);
		return (EXIT_FAILURE);
	}else{
		memcpy(pktbuf_rip,pdata,plen);
		gipheader->tot_len = htons(pktlen);
		gipheader->id = ripheader->id;
		gipheader->check = 0;
		gipheader->check = chksum((unsigned short *)gipheader, SIZE_HEADER_IP/sizeof(unsigned short));

		return nfq_set_verdict(qh, id, NF_ACCEPT, pktlen, (unsigned char *)pktbuf);	//-1 on error; >= 0 otherwise.
	}
}

static void nfq_qh_destroy(void *tinfo){
	char message[SIZE_MSG+1];

	nfq_destroy_queue(((struct thread_info *)tinfo)->thread_nfq_qh);
	((struct thread_info *)tinfo)->thread_do_exit = true;
	snprintf(message,SIZE_MSG,"Thread %d Canceled",((struct thread_info *)tinfo)->thread_num);
	info_print(message);
}

static void *thread_nfq(void *arg){
	struct thread_info *tinfo_this = (struct thread_info *)arg;
	struct nfq_q_handle *nfq_qh;
	int fd,rv=0;
	struct nfq_cb_info ncinfo;
	char pktbuf[SIZE_ETHER_MTU];
	char *pktbuf_gre = (char *)(pktbuf + SIZE_HEADER_IP);
	struct iphdr *gipheader = (struct iphdr *)pktbuf;
	char buf[4096] __attribute__((aligned));
	char tmessage[SIZE_MSG+1]={0};
	bool thread_in_use=false;

	memset(pktbuf, 0x00, sizeof(pktbuf));

	memcpy(pktbuf_gre, greheader, SIZE_HEADER_GRE);
	gipheader->version = 4;
	gipheader->ihl = 5;
	gipheader->ttl = 0xFF;
	gipheader->protocol = 0x2F;
	gipheader->saddr = inet_addr(bindip);
	gipheader->daddr = inet_addr(relayip);

	ncinfo.thread_num = tinfo_this->thread_num;
	ncinfo.pktbuf = pktbuf;
	ncinfo.pktbuf_rip = (char *)(pktbuf + SIZE_HEADER_IP + SIZE_HEADER_GRE);
	ncinfo.message = tmessage;

	nfq_qh = nfq_create_queue(nfq_h, tinfo_this->thread_num, &nfq_mycallback, &ncinfo);
	if(!nfq_qh){
		snprintf(tmessage, SIZE_MSG, "nfq_create_queue() FAIL in Thread %d", tinfo_this->thread_num);
		error_print(tmessage, false);
		tinfo_this->thread_do_exit = true;
		pthread_exit("thread exit\n");
	}
	tinfo_this->thread_nfq_qh = nfq_qh;
	pthread_cleanup_push(nfq_qh_destroy, tinfo_this);
	if (nfq_set_mode(nfq_qh, NFQNL_COPY_PACKET, 0xFFFF) < 0){
		snprintf(tmessage, SIZE_MSG, "nfq_set_mode() FAIL in Thread %d", tinfo_this->thread_num);
		error_print(tmessage, false);
		nfq_destroy_queue(nfq_qh);
		tinfo_this->thread_do_exit = true;
		pthread_exit("thread exit\n");
	}
	tinfo_this->thread_succ = true;
	snprintf(tmessage,SIZE_MSG, "NFQUEUE %d Thread Created", tinfo_this->thread_num);
	info_print(tmessage);
	fd = nfq_fd(nfq_h);
	while(running){
		rv = recv(fd, buf, sizeof(buf), 0);
		if(rv >= 0)
			nfq_handle_packet(nfq_h, buf, rv);
		if(!thread_in_use){
			thread_in_use = true;
			snprintf(tmessage,SIZE_MSG, "Thread %d IN USE", tinfo_this->thread_num);
			info_print(tmessage);
		}
		tinfo_this->thread_packets += 1;
	}
	if(running && rv == -1){
		snprintf(tmessage, SIZE_MSG, "recv() Failed in Thread %d", tinfo_this->thread_num);
		error_print(tmessage, false);
		nfq_destroy_queue(nfq_qh);
		tinfo_this->thread_do_exit = false;
		pthread_exit("thread exit\n");
	}
	pthread_cleanup_pop(1);
	pthread_exit("thread exit\n");
}

int main(int argc, char** argv){
	int opt,num_arg=3,t_res,result;												//num_arg: 0-> : b,r
	bool daemon_mode=false;
	void *thread_res;
	char *logpath=NULL;

	running = true;

	sig_handler_register();
	print_mutex_init();

	while((opt = getopt(argc, argv, "b:df:hr:t:")) != -1){
		switch(opt){
			case 'b':
				result = strlen(optarg);
				if(result > SIZE_IP_STR){
					snprintf(message, SIZE_MSG, "argument error: -b %s, error IP addr", optarg);
					error_print(message,false);
					exit_on_error();
				}
				bindip = optarg;
				num_arg &= ~(1<<0);
				break;
			case 'r':
				result = strlen(optarg);
				if(result > SIZE_IP_STR){
					snprintf(message, SIZE_MSG, "argument error: -r %s, error IP addr", optarg);
					error_print(message,false);
					exit_on_error();
				}
				relayip = optarg;
				num_arg &= ~(1<<1);
				break;
			case 'd':
				daemon_mode = true;
				break;
			case 'f':
				logpath = optarg;
				break;
			case 't':
				result = atoi(optarg);
				if(result<1 || result>12){
					snprintf(message, SIZE_MSG, "argument error: -t %s, thread number should be in range [1-12]", optarg);
					error_print(message,false);
					exit_on_error();
				}
				num_threads = result;
				break;
			case 'h':
			default:
				usage_print();
				exit_on_error();
		}
	}
	if(num_arg != 0){
		usage_print();
		exit(EXIT_FAILURE);
	}

	if(!logpath && daemon_mode)													//为守护进程模式设置默认日志文件路径
		logpath = LOG_PATH;
	if(logpath &&  freopen((const char *)logpath, "a", stderr) == NULL){		//重定向stderr至指定日志文件
		error_print("freopen()", true);
		exit_on_error();
	}
	snprintf(message, SIZE_MSG, "Using Log File %s", logpath);
	info_print(message);
	snprintf(message, SIZE_MSG, "%spid:%d", p_name, getpid());
	info_print(message);

	if(daemon_mode){															//尝试进入守护进程模式
		result = daemon(1, 1);
		if(result == 0){
			info_print("RUN_IN_DAEMON_MODE");
			snprintf(message, SIZE_MSG, "%sdpid:%d", p_name, getpid());
			info_print(message);
		}else{
			error_print("daemon()", true);
			daemon_mode = false;
		}
	}
	if(!daemon_mode)															//未能进入守护进程模式
		info_print("RUN_IN_NORMAL_MODE");

	nfq_h_open();

	tinfo = calloc(num_threads,sizeof(struct thread_info));

	for(int i=0;i<num_threads;i++){	//C99
		tinfo[i].thread_num = i;
		tinfo[i].thread_do_exit = true;
		tinfo[i].thread_succ = false;
		tinfo[i].thread_fail_num = 0;
		tinfo[i].thread_packets = 0;
		t_res = pthread_create(&tinfo[i].thread_id, NULL, &thread_nfq, &tinfo[i]);
		if(t_res != 0)
			pth_error_exit("pthread_create()", t_res);
	}

	for(int i=0; i<num_threads; i++)
		while(running && !tinfo[i].thread_succ){
			usleep(TIME_THREAD_CH);
		}
	info_print("nfqresult:SUCCESS");

	while(running){
		for(int i=0; i<num_threads; i++){
			t_res = pthread_tryjoin_np(tinfo[i].thread_id, &thread_res);
			if(t_res != 0){
				if(t_res != EBUSY)
					pth_error_exit("pthread_tryjoin_np()",t_res);
			}else if(running && !tinfo[i].thread_do_exit){
				tinfo[i].thread_fail_num += 1;
				snprintf(message,SIZE_MSG,"Thread %d Down",tinfo[i].thread_num);
				error_print(message,false);
				if(tinfo[i].thread_fail_num < THREAD_RETRY_TIMES){
					snprintf(message,SIZE_MSG,"Try to Restart Thread %d",tinfo[i].thread_num);
					error_print(message,false);
					t_res = pthread_create(&tinfo[i].thread_id, NULL, &thread_nfq, &tinfo[i]);
					if(t_res != 0)
						pth_error_exit("pthread_create()", t_res);
					snprintf(message,SIZE_MSG,"Thread %d Up",tinfo[i].thread_num);
					error_print(message,false);
				}else{
					tinfo[i].thread_do_exit = true;
					snprintf(message,SIZE_MSG,"Thread %d Exit",tinfo[i].thread_num);
					error_print(message,false);
				}
			}else if(running && tinfo[i].thread_fail_num < THREAD_RETRY_TIMES){
				tinfo[i].thread_fail_num = THREAD_RETRY_TIMES;
				snprintf(message,SIZE_MSG,"Thread %d Exit",tinfo[i].thread_num);
				error_print(message,false);
			}
		}
		sleep(TIME_TO_WAIT);
	}

	for(int i=0;i<num_threads;i++){
		t_res = pthread_join(tinfo[i].thread_id, &thread_res);
		if(t_res != 0)
			pth_error_exit("pthread_join()", t_res);
		snprintf(message,SIZE_MSG, "Thread %d Exit, With %d Packets Handled", tinfo[i].thread_num, tinfo[i].thread_packets);
		info_print(message);
	}

	free(tinfo);
	nfq_h_close();
	return (EXIT_SUCCESS);
}
