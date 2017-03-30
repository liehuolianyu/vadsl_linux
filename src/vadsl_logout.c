
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "vadsl_common.h"

#define H_P_LEN 2
#define PH_P_LEN 3

#define GW_PORT 1812

#define SIZE_ACCOUNT	14
#define SIZE_SBUF		100
#define SIZE_PHEADER	8
#define SIZE_HEADER		4
#define SIZE_ADDR_IP	4
#define SIZE_STR_IP		16
#define SIZE_ACCOUNT_END	4

char *p_name="vadsl_logout";
unsigned char pheader_stop[] =	{ 0x5f, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char header_sip[] =	{ 0x14, 0x01, 0x00, 0x00 };
unsigned char header_sacnt[] =	{ 0x14, 0x03, 0x12, 0x00 };

const char end[] = { 0x00, 0x00, 0x00, 0x00 };

void error_print(char *str, bool use_errno){
	error_print_nolock(str, use_errno);
}

void info_print(char *str){
	info_print_nolock(str);
}

/*
 * -i interface -s authserver -a account
 */
int main(int argc, char** argv) {
	int sockfd;
	int len;
	in_addr_t ipaddr_int;
	char *ipaddr;														//IP地址，字符串，长度IP_LEN
	struct sockaddr_in address;
	int result;
	char *bindip,*authserver,*account;
	char packet_sbuf[SIZE_SBUF];
	int packet_slen=0;

	if(argc == 7 && !strcmp(argv[1],"-b") && !strcmp(argv[3],"-s") && !strcmp(argv[5],"-a")){
		bindip = argv[2];
		len = strlen(bindip);
		if(len > SIZE_STR_IP){
			fprintf(stdout,"error: bind IP addr too long\n");
			exit(EXIT_FAILURE);
		}
		authserver = argv[4];
		len = strlen(authserver);
		if(len > SIZE_STR_IP){
			fprintf(stdout,"error: gateway addr too long\n");
			exit(EXIT_FAILURE);
		}
		account = argv[6];
		len = strlen(account);
		if(len > SIZE_ACCOUNT){
			fprintf(stdout,"error: account name too long\n");
			exit(EXIT_FAILURE);
		}
	}else{
		fprintf(stdout,"usage: -b <bind IP> -s <auth server> -a <account>\n");
		exit(EXIT_FAILURE);
	}

	sockfd = socket(AF_INET,SOCK_STREAM,0);
	if(sockfd == -1){
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	ipaddr_int = inet_addr(bindip);												//获取IP地址
	ipaddr = (char *)&ipaddr_int;

	memset(&packet_sbuf, 0x00, SIZE_SBUF);
	strcpy(packet_sbuf,(const char *)pheader_stop);
	packet_slen += SIZE_PHEADER;

	header_sip[H_P_LEN] = SIZE_HEADER + SIZE_ADDR_IP;							//ip
	strcpy((char *)(packet_sbuf+packet_slen),(const char *)header_sip);
	packet_slen += SIZE_HEADER;
	strncpy((char *)(packet_sbuf+packet_slen),(const char *)ipaddr,SIZE_ADDR_IP);
	packet_slen += SIZE_ADDR_IP;

	len = strlen(account);
	header_sacnt[H_P_LEN] = SIZE_HEADER + len + SIZE_ACCOUNT_END;				//account
	strcpy((char *)(packet_sbuf+packet_slen),(const char *)header_sacnt);
	packet_slen += SIZE_HEADER;
	strncpy((char *)(packet_sbuf+packet_slen),(const char *)account,len);
	packet_slen += len;
	strncpy((char *)(packet_sbuf+packet_slen),end,SIZE_ACCOUNT_END);
	packet_slen += SIZE_ACCOUNT_END;

	packet_sbuf[PH_P_LEN] = packet_slen - SIZE_PHEADER;

	strcpy((char *)(packet_sbuf+packet_slen),end);
	packet_slen += sizeof(end);
	strcpy((char *)(packet_sbuf+packet_slen),end);
	packet_slen += sizeof(end);													//Packet Length

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(authserver);
	address.sin_port = htons(GW_PORT);
	len = sizeof(address);

	result = connect(sockfd,(struct sockaddr *)&address,len);
	if(result == -1){
		error_print("connect()", true);
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	result = write(sockfd,packet_sbuf,packet_slen);
	if(result == -1){
		error_print("write()", true);
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	info_print("LOGOUT Request Has Been Sent");

	name_print(stdout);
	time_print(stdout, "logout time");

	close(sockfd);
	return (EXIT_SUCCESS);
}
