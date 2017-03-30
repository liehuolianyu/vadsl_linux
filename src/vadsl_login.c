
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <iconv.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>		//Declarations of socket constants, types, and functions
#include <net/if.h>		//Declarations for inquiring about network interfaces
#include <netinet/in.h>

#include "vadsl_common.h"

#define H_P_LEN 2		//头部长度位置
#define H_P_TYPE 1		//头部类型位置
#define PH_P_LEN 2		//数据包头部长度位置
#define PH_P_TYPE 1		//数据包头部类型位置

#define PASS_END_L 1		//密码结束字符长度，密码结束字符为ip地址最后一位
//接收到数据包头部类型
#define AUTH_SUCCESS 0x51	//认证成功
#define AUTH_FAILURE 0x52	//认证失败
#define AUTH_MESSAGE 0xE0	//认证消息
//接收到数据头部类型
#define R_RADDR_5	0x05	//接收--网关地址
#define R_UNKOWN	0x06	//接收--未知数据
#define R_RADDR_7	0x07
#define R_ROUTE_FLT	0x09	//接收--路由过滤信息
#define R_LEFT_TIME	0x0A	//接收--剩余时间
#define R_MSG		0x15	//接收--文本消息

#define RF_P_NUM	8
#define RF_P_LIST	12
#define SIZE_RF_BLOCK	12

#define GW_PORT 1812
#define AUTO_LOGOFF 4

#define TIME_SLEEP 240

#define SERVER_CODE	"gb2312"	//服务器中文默认编码
#define LOCAL_CODE	"utf-8"		//本地中文默认编码

#define SIZE_MESSAGE	200		//服务器中文消息缓存大小
#define SIZE_SBUF		100	//发送数据缓存大小
#define SIZE_ACCOUNT_END	4
#define SIZE_ACCOUNT_MAX	20
#define SIZE_HEADER		4
#define SIZE_PHEADER	8
#define SIZE_ADDR_HDW	6
#define SIZE_ADDR_IP	4
#define SIZE_STR_IP		16
#define SIZE_STR_IF		8
#define SIZE_PASSWD		16
#define SIZE_MSG	100

char *p_name="vadsl_login";
char pmessage[SIZE_MSG+1]={0};

struct header_str{		//头部结构
	uint8_t h_dir;
	uint8_t h_type;
	uint8_t h_len;
	uint8_t h_unuse;
};
//发送数据包头部类型
unsigned char pheader_start[] =	{0x5f, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};	//请求建立连接
unsigned char pheader_sack[] =	{0x5f, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};	//确认建立连接
unsigned char pheader_scntu[] = {0x5f, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};	//继续连接
unsigned char pheader_stop[] =	{0x5f, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};	//取消连接
//发送数据头部类型
unsigned char header_smac[] =	{ 0x14, 0x02, 0x00, 0x00 };	//MAC头部
unsigned char header_sip[] =	{ 0x14, 0x01, 0x00, 0x00 };	//IP地址头部
unsigned char header_sacnt[] =	{ 0x14, 0x03, 0x00, 0x00 };	//帐号头部
unsigned char header_spass[] =	{ 0x14, 0x04, 0x00, 0x00 };	//密码头部
unsigned char header_svers[] =	{ 0x14, 0x05, 0x00, 0x00 };	//版本头部
unsigned char header_send[] =	{ 0x14, 0x06, 0x00, 0x00 };	//结尾(未知)头部

unsigned char version[] = { 0x03, 0x01, 0x00, 0x1c };		//版本
const char end[] = { 0x00, 0x00, 0x00, 0x00 };			//结尾（未知）

int code_convert(	char *from_charset, char *to_charset, char *inbuf,int len_in,
					char *outbuf, int len_out){
	iconv_t cd;
	char **pin = &inbuf;
	char **pout = &outbuf;
	size_t inlen = len_in;
	size_t outlen = len_out;

	cd = iconv_open(to_charset,from_charset);
	if (cd==0)
		return -1;
	memset(outbuf,0x00,outlen);
	if (iconv(cd,pin,&inlen,pout,&outlen) == (size_t)-1)
		return -1;
	iconv_close(cd);
	return 0;
}

void error_print(char * str){
	error_print_nolock(str, true);
}

void info_print(char *str){
	info_print_nolock(str);
}

void network_log(unsigned char * content,int num){
	fprintf( stderr,"\t\tRF%.2d:%u.%u.%u.%u/%u.%u.%u.%u\n",(num+1),content[0],content[1],
					content[2],content[3],content[4],content[5],content[6],content[7] );
}

int info_unpack(unsigned char * content,int len){
	int i,j;
	struct header_str * h_str_tmp;
	uint32_t left_time;
	unsigned char * tmp;
	uint8_t rf_num;
	for(i=0;i<len;){
		h_str_tmp = (struct header_str *)(content + i);
		switch(h_str_tmp->h_type){
			case R_LEFT_TIME:			//剩余时间
				left_time = ntohl(*(uint32_t *)(content + i + SIZE_HEADER));
				fprintf(stdout,"\trest avaliable time: \t%uh%um%us\n",left_time/3600,left_time%3600/60,left_time%60);
				fprintf(stderr,"\tTime remaining: %uh%um%us\n",left_time/3600,left_time%3600/60,left_time%60);
				break;
			case R_RADDR_5:				//转接网关地址
				tmp = (unsigned char *)(content + i + SIZE_HEADER);
				fprintf(stdout,"\ttransfer gateway addr: \t%u.%u.%u.%u\n",tmp[0],tmp[1],tmp[2],tmp[3]);
				fprintf(stderr,"\tRelay IP: %u.%u.%u.%u\n",tmp[0],tmp[1],tmp[2],tmp[3]);
				break;
			case R_UNKOWN:				//目前未知数据
				tmp = (unsigned char *)(content + i + SIZE_HEADER);
				fprintf(stderr,"\tUnkownData:\t");
				for(j=0;j<(h_str_tmp->h_len-SIZE_HEADER);j++)
					fprintf(stderr,"%.2X ",tmp[j]);
				fprintf(stderr,"\n");
				break;
			case R_ROUTE_FLT:			//路由过滤地址
				rf_num = content[i + SIZE_HEADER + RF_P_NUM];
				fprintf(stderr,"\tRouterFilterInfo:\n");
				for(j=0;j<rf_num;j++)
					network_log((unsigned char *)(content+i+SIZE_HEADER+RF_P_LIST+j*SIZE_RF_BLOCK),j);
				break;
			default:
				break;
		}
		i += h_str_tmp->h_len;
	}
	return 0;
}

void packet_print(FILE * stream,unsigned char * start,int len){
	int i;
	fprintf(stream,"\t");
	for(i=0; i<len;i++){
		fprintf(stream,"%.2X ",start[i]);
		if( i%4 == 3 )
			fprintf(stream," ");
		if( i%16 == 15 && i < (len-1))
			fprintf(stream,"\n\t");
	}
	fprintf(stream,"\n");
}
/*
 *
 */
int main(int argc, char** argv) {
	int sockfd;
	struct ifreq hdw_buf;
	int i,len,result;					//临时计数变量、临时长度变量、临时整型返回值变量
	char hdwaddr[SIZE_ADDR_HDW] = {0};			//MAC地址，字符串，长度HDW_LEN
	const unsigned char ipaddr[SIZE_ADDR_IP] = {0};
	struct in_addr * ipaddr_int = (struct in_addr *)ipaddr;			//IP地址，32位整型
	unsigned char packet_rheader[SIZE_PHEADER];				//接收数据头部缓存
	uint16_t * packet_len = (uint16_t *)(packet_rheader + PH_P_LEN);
	unsigned char * packet_rbuf;						//接收数据内容缓存
	char * msg_r;								//接收消息指针（服务器编码）
	char *message;								//接收消息缓存（本地编码）
	char packet_sbuf[SIZE_SBUF];						//发送数据缓存
	int packet_slen = 0;							//发送数据长度
	char *interface,*account,*password,*authserver,*logpath;
	struct sockaddr_in as_addr;						//认证网关
	int as_addr_len;
	int continue_error = 0;							//维持连接数据包发送失败次数

	/**************************参数处理及认证信息*******************************/
	if(argc == 11 && !strcmp(argv[1],"-i") && !strcmp(argv[3],"-s") &&	//参数处理
					!strcmp(argv[5],"-a") && !strcmp(argv[7],"-p") && !strcmp(argv[9],"-f")){
		interface = argv[2];
		len = strlen((const char *)interface);
		if(len > SIZE_STR_IF){
			error_print("error: network interface too long\n");
			exit(EXIT_FAILURE);
		}
		authserver = argv[4];
		len = strlen((const char *)authserver);
		if(len > SIZE_STR_IP){
			error_print("error: gateway addr too long\n");
			exit(EXIT_FAILURE);
		}
		account = argv[6];
		len = strlen((const char *)account);
		if(len > SIZE_ACCOUNT_MAX){
			error_print("error: account name too long\n");
			exit(EXIT_FAILURE);
		}
		password = argv[8];
		len = strlen((const char *)password);
		if(len > SIZE_PASSWD){
			error_print("error: password too long\n");
			exit(EXIT_FAILURE);
		}
		logpath = argv[10];
	}else{
		name_print(stdout);
		fprintf(stdout,"usage: -i <network interface> -s <auth server> -a <account> -p <password> -f <log file>\n");
		exit(EXIT_FAILURE);
	}

	if(freopen((const char *)logpath,"a",stderr) == NULL){
		error_print("freopen()");
		exit(EXIT_FAILURE);
	}

	snprintf(pmessage,  SIZE_MSG, "%spid:%d", p_name, getpid());
	info_print(pmessage);

	sockfd = socket(AF_INET,SOCK_STREAM,0);				//创建套接字
    if(sockfd == -1){
        error_print("socket()");
        exit(EXIT_FAILURE);
    }

	memset(&hdw_buf, 0x00, sizeof(hdw_buf));			//获取MAC地址
	strcpy(hdw_buf.ifr_name, interface);
	ioctl(sockfd, SIOCGIFHWADDR, &hdw_buf);
	strncpy(hdwaddr,(const char *)hdw_buf.ifr_hwaddr.sa_data,SIZE_ADDR_HDW);

	memset(&hdw_buf, 0x00, sizeof(hdw_buf));			//获取IP地址
	strcpy(hdw_buf.ifr_name, interface);
	ioctl(sockfd, SIOCGIFADDR, &hdw_buf);
	ipaddr_int->s_addr = ((struct sockaddr_in *)&hdw_buf.ifr_addr)->sin_addr.s_addr;

	len = strlen(password);						//密码变换，异或ipaddr最后一位
	for( i=0 ; i < len ; i++ )
		password[i] = password[i] ^ ipaddr[3];
	/******************************构造初始认证Packet***************************/
	memset(&packet_sbuf, 0x00, sizeof(packet_sbuf));
	memcpy((void *)packet_sbuf, (const void *)pheader_start, SIZE_PHEADER);
	packet_slen = SIZE_PHEADER;

	header_smac[H_P_LEN] = SIZE_HEADER + SIZE_ADDR_HDW;		//mac
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)header_smac, SIZE_HEADER);
	packet_slen += SIZE_HEADER;
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)hdwaddr, SIZE_ADDR_HDW);
	packet_slen += SIZE_ADDR_HDW;

	header_sip[H_P_LEN] = SIZE_HEADER + SIZE_ADDR_IP;		//ip
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)header_sip, SIZE_HEADER);
	packet_slen += SIZE_HEADER;
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)ipaddr, SIZE_ADDR_IP);
	packet_slen += SIZE_ADDR_IP;

	len = strlen(account);
	header_sacnt[H_P_LEN] = SIZE_HEADER + len + SIZE_ACCOUNT_END;	//account
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)header_sacnt, SIZE_HEADER);
	packet_slen += SIZE_HEADER;
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)account, (size_t)len);
	packet_slen += len;
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)end, SIZE_ACCOUNT_END);
	packet_slen += SIZE_ACCOUNT_END;

	len = strlen(password);
	header_spass[H_P_LEN] = SIZE_HEADER + len + PASS_END_L;		//password
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)header_spass, SIZE_HEADER);
	packet_slen += SIZE_HEADER;
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)password, (size_t)len);
	packet_slen += len;
	packet_sbuf[packet_slen] = ipaddr[3];				//密码附加为ip地址最后一位
	packet_slen += PASS_END_L;

	header_svers[H_P_LEN] = SIZE_HEADER + sizeof(version);		//Version
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)header_svers, SIZE_HEADER);
	packet_slen += SIZE_HEADER;
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)version, sizeof(version));
	packet_slen += sizeof(version);

	header_send[H_P_LEN] = SIZE_HEADER + sizeof(end);		//END
	memcpy((void *)(packet_sbuf+packet_slen),(const void *)header_send, SIZE_HEADER);
	packet_slen += SIZE_HEADER;
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)end, sizeof(end));
	packet_slen += sizeof(end);					//Packet Length

	*(uint16_t *)(packet_sbuf + PH_P_LEN) = htons(packet_slen -SIZE_PHEADER);	//Packet_Header_LEN_INFO
	/*****************************发送认证数据**********************************/
	as_addr.sin_family = AF_INET;
	as_addr.sin_addr.s_addr = inet_addr(authserver);
    as_addr.sin_port = htons(GW_PORT);
	as_addr_len = sizeof(as_addr);

	result = connect(sockfd,(struct sockaddr *)&as_addr,as_addr_len);
    if(result == -1){
        error_print("connect()");
		close(sockfd);
        exit(EXIT_FAILURE);
    }

	result = write(sockfd,packet_sbuf,packet_slen);
    if(result == -1){
        error_print("write()");
		close(sockfd);
        exit(EXIT_FAILURE);
    }

	name_print(stdout);
	fprintf(stdout,"auth data send to %s:%d, %d Byte\n",authserver,GW_PORT,result);
	snprintf(pmessage, SIZE_MSG, "Auth Request Has Been Sent To %s", authserver);
	info_print(pmessage);
	/**************************接收并处理服务器回送信息**************************/
	result = read(sockfd,packet_rheader,SIZE_PHEADER);			//读取Packet Header信息
	if(result == -1){
		error_print("read()");
		name_print(stdout);
		fprintf(stdout,"can not read data, program error and exit, please see log file\n");
		close(sockfd);
        exit(EXIT_FAILURE);
	}
	packet_rbuf = malloc(ntohs(*packet_len));
	result = read(sockfd,packet_rbuf,ntohs(*packet_len));			//取回有用数据
	if(result == -1){
		error_print("read()");
		name_print(stdout);
		fprintf(stdout,"can not raed data, program error and exit, please see log file\n");
		close(sockfd);
        exit(EXIT_FAILURE);
	}

	if(packet_rheader[PH_P_TYPE] == AUTH_FAILURE){				//认证失败处理
		name_print(stdout);
		fprintf(stdout,"auth fail, server return msg: \n");
		info_print("AuthResult:FAILURE");
		info_print("AuthFailureReason:");
		if(packet_rbuf[H_P_TYPE] == R_MSG){				//认证失败原因
			msg_r = (char *)(packet_rbuf+4);
			len = strlen(msg_r);
			message = malloc(2*len);
			result = code_convert(SERVER_CODE,LOCAL_CODE,msg_r,len,message,2*len);
			if(result == -1)
				error_print("code_convert()");
			else{
				fprintf(stdout,"\t%s\n",message);
				fprintf(stderr,"\t%s\n",message);
			}

			free(message);
			free(packet_rbuf);
			close(sockfd);
			exit(EXIT_FAILURE);
		}else
			packet_print(stdout,packet_rbuf,ntohs(*packet_len));
	}else if(packet_rheader[PH_P_TYPE] == AUTH_SUCCESS){			//认证成功
		info_print("AuthResult:SUCCESS");
		info_print("Information Returned by Server:");
		name_print(stdout);
		fprintf(stdout,"auth OK, server return info: \n");
		info_unpack(packet_rbuf,ntohs(*packet_len));

		result = write(sockfd,pheader_sack,SIZE_PHEADER);		//发送登录确认数据包
		if(result == -1){
			error_print("write()");
			free(packet_rbuf);
			close(sockfd);
			exit(EXIT_FAILURE);
		}

		name_print(stdout);
		time_print(stdout,"connection setup");

		free(packet_rbuf);
		close(sockfd);
	}else{
		info_print("AuthResult:FAILURE");

		name_print(stderr);
		fprintf(stderr,"UnkownReturnInfo:\nHeader:\n");
		packet_print(stderr,packet_rheader,SIZE_PHEADER);
		fprintf(stderr,"Content:\n");
		packet_print(stderr,packet_rbuf,ntohs(*packet_len));

		name_print(stdout);
		fprintf(stdout,"server return unknow data, exit\n");

		free(packet_rbuf);
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	/************************构造保持数据包*************************************/
	memset(&packet_sbuf, 0x00, sizeof(packet_sbuf));
	memcpy((void *)packet_sbuf, (const void *)pheader_scntu, SIZE_PHEADER);
	packet_slen = SIZE_PHEADER;

	memcpy((void *)(packet_sbuf+packet_slen), (const void *)header_sip, SIZE_HEADER);			//ip
	packet_slen += SIZE_HEADER;
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)ipaddr, SIZE_ADDR_IP);
	packet_slen += SIZE_ADDR_IP;

	len = strlen((const char *)account);
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)header_sacnt, SIZE_HEADER);		//account
	packet_slen += SIZE_HEADER;
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)account, (size_t)len);
	packet_slen += len;
	memcpy((void *)(packet_sbuf+packet_slen), (const void *)end, SIZE_ACCOUNT_END);
	packet_slen += SIZE_ACCOUNT_END;

	*(uint16_t *)(packet_sbuf + PH_P_LEN) = htons(packet_slen -SIZE_PHEADER);
	/***********************间隔240s向认证服务器发送保持在线数据包***************/
//	fprintf(stdout,"开始间隔%ds向认证服务器发送保持连接数据包\n",TIME_SLEEP);

	result = daemon(1,1);
	if(result == 0){
		snprintf(pmessage, SIZE_MSG, "%sdpid:%d", p_name, getpid());
		info_print(pmessage);
	}else{
		error_print("daemon()");
		name_print(stdout);
		fprintf(stdout,"can not run in background\n");
	}

	while(1){
		if(continue_error > AUTO_LOGOFF){
			name_print(stderr);
			fprintf(stderr,"long time not to connect to auth server, auto logout\n");
			exit(EXIT_FAILURE);
			break;
		}

		fflush(stderr);
		sleep(TIME_SLEEP);

		sockfd = socket(AF_INET,SOCK_STREAM,0);			//创建套接字
		if(sockfd == -1){
			error_print("connection keep data send error\nsocket()");
			continue_error++;
			continue;
		}

		result = connect(sockfd,(struct sockaddr *)&as_addr,as_addr_len);
		if(result == -1){
			error_print("connection keep data send error\nconnect()");
			close(sockfd);
			continue_error++;
			continue;
		}

		result = write(sockfd,packet_sbuf,packet_slen);
		if(result == -1){
			error_print("connection keep data send error\nwrite()");
			close(sockfd);
			continue_error++;
			continue;
		}

		continue_error = 0;
		close(sockfd);
	}

	fflush(stderr);
	exit(EXIT_SUCCESS);
}
