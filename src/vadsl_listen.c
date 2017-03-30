
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <iconv.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SIZE_STR_IP		15
#define SIZE_STR_PORT	5
#define SIZE_PHEADER	8

#define LISTEN_BACKLOG	5

#define SERVER_TO_HOST	0x15
#define HOST_TO_SERVER	0x14

#define PH_COMMON	0x5f

#define AUTH_MSG	0xe0
#define R_MSG		0x15

#define PH_P_COMMON	0
#define PH_P_TYPE	1
#define PH_P_LEN	3

#define H_P_TYPE 1

#define SERVER_CODE	"gb2312"
#define LOCAL_CODE	"utf-8"

#define LISTEN_PORT 1812

void print_time(){
	time_t time_std;
	struct tm * time_str;

	time(&time_std);
	time_str = localtime(&time_std);
	fprintf(stdout,"\ntime: %d h %d m %d s\n",time_str->tm_hour,
								time_str->tm_min , time_str->tm_sec );
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
	if (iconv(cd,pin,&inlen,pout,&outlen) == -1)
		return -1;
	iconv_close(cd);
	return 0;
}
/*
 * -b <bindip> -g <gateway>
 */
int main(int argc, char** argv) {
	int sockfd,len,clientfd;
	struct sockaddr_in bindip,gateway,client;
	socklen_t client_addr_len;
	unsigned char packet_rheader[SIZE_PHEADER];									//接收数据头部缓存
	unsigned char * packet_rbuf;												//接收数据内容缓存
	char * msg_r;																//接收消息指针（服务器编码）
	char * message;																//接收消息缓存（本地编码）
	unsigned char * client_addr;
	int result;

	if(argc == 5 && !strcmp(argv[1],"-b") && !strcmp(argv[3],"-g")){
		len = strlen(argv[2]);
		if(len > SIZE_STR_IP){
			fprintf(stdout,"bind IP addr args error\n");
			exit(EXIT_FAILURE);
		}
		memset(&bindip, 0, sizeof(struct sockaddr_in));
		bindip.sin_family = AF_INET;
		bindip.sin_addr.s_addr = inet_addr(argv[2]);
		bindip.sin_port = htons(LISTEN_PORT);
		len = strlen(argv[4]);
		if(len > SIZE_STR_IP){
			fprintf(stdout,"auth gateway addr args error\n");
			exit(EXIT_FAILURE);
		}
		memset(&gateway, 0, sizeof(struct sockaddr_in));
		gateway.sin_family = AF_INET;
		gateway.sin_addr.s_addr = inet_addr(argv[4]);
	}else{
		fprintf(stdout,"usage: -b <bind IP addr> -g <auth gateway>\n");
		exit(EXIT_FAILURE);
	}

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1){
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	len = sizeof(struct sockaddr_in);
	if ( bind( sockfd, (struct sockaddr *)&bindip,len ) == -1 ){
		perror("bind()");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	if (listen(sockfd, LISTEN_BACKLOG) == -1){
		perror("listen()");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	while(1){
		clientfd = accept(sockfd,(struct sockaddr *) &client,&client_addr_len);
		if( clientfd == -1 ){
			perror("accept()");
			close(sockfd);
			exit(EXIT_FAILURE);
		}

		print_time();
		getpeername(clientfd, (struct sockaddr *) &client,&client_addr_len);
		client_addr = (unsigned char *)&client.sin_addr.s_addr;
		fprintf( stdout,"recv from %d.%d.%d.%d connection request \n",client_addr[0],client_addr[1],
													  client_addr[2],client_addr[3] );

		read(clientfd,packet_rheader,SIZE_PHEADER);								//读取Packet Header信息

		if(packet_rheader[PH_P_COMMON] != PH_COMMON){
			fprintf(stdout,"unknow data, include error header info, ignore\n");
		}else{
			packet_rbuf = malloc(packet_rheader[PH_P_LEN]);
			read(clientfd,packet_rbuf,packet_rheader[PH_P_LEN]);
			switch(packet_rheader[PH_P_TYPE]){
				case AUTH_MSG:
					if(packet_rbuf[H_P_TYPE] == R_MSG){
						msg_r = (char *)(packet_rbuf+4);
						len = strlen(msg_r);
						fprintf(stdout,"recv msg, len: %d Byte, content: \n",len);
						message = malloc(2*len);
						result = code_convert(SERVER_CODE,LOCAL_CODE,msg_r,len,message,2*len);
						if(result == -1)
							perror("code_convert()");
						else
							fprintf(stdout,"\t%s\n",message);
						free(message);
					}else{
						fprintf(stdout,"recv msg, unknow type, header: \n");
						packet_print(stdout,packet_rheader,SIZE_PHEADER);
						fprintf(stdout,"content: \n");
						packet_print(stdout,packet_rbuf,packet_rheader[PH_P_LEN]);
					}
					break;
				default:
					fprintf(stdout,"recv msg, unknow type, header: \n");
					packet_print(stdout,packet_rheader,SIZE_PHEADER);
					fprintf(stdout,"content: \n");
					packet_print(stdout,packet_rbuf,packet_rheader[PH_P_LEN]);
					break;
			}

			free(packet_rbuf);
		}

		close(clientfd);
	}

	return (EXIT_SUCCESS);
}
