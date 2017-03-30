
#include <stdio.h>
#include <stdlib.h>
#include <iconv.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SIZE_STR_IP	16
#define SIZE_PHEADER	8
#define SIZE_HEADER	4
#define SIZE_MSG_END	2

#define PH_P_LEN	3
#define P_P_LEN	2

#define SERVER_PORT	1812

#define SERVER_CODE	"gb2312"													//服务器中文默认编码
#define LOCAL_CODE	"utf-8"														//本地中文默认编码

unsigned char pheader_smsg[SIZE_PHEADER] = { 0x5f, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char header_smsg[SIZE_HEADER] = { 0x15, 0x15, 0x00, 0x00 };
unsigned char msg_end[SIZE_MSG_END] = { 0x00, 0xcc };

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
 * -h <host> -m <message>
 */
int main(int argc, char** argv) {
	int sockfd,len,result;
	struct sockaddr_in host;
	char *msg_utf8,*msg_gbk;
	int msg_len_u,msg_len_g;

	if(argc == 5 && !strcmp(argv[1],"-h") && !strcmp(argv[3],"-m")){
		len = strlen(argv[2]);
		if(len > SIZE_STR_IP){
			fprintf(stdout,"host addr args error\n");
			exit(EXIT_FAILURE);
		}
		host.sin_family = AF_INET;
		host.sin_addr.s_addr = inet_addr(argv[2]);
		host.sin_port = htons(SERVER_PORT);
		msg_utf8 = argv[4];
		msg_len_u = strlen(msg_utf8);
	}else{
		fprintf(stdout,"usage: -h <host addr> -m <msg>\n");
		exit(EXIT_FAILURE);
	}

	msg_gbk = malloc(2*msg_len_u);
	result = code_convert(LOCAL_CODE,SERVER_CODE,msg_utf8,msg_len_u,msg_gbk,2*msg_len_u);
	if(result == -1){
		perror("code_convert()");
		exit(EXIT_FAILURE);
	}

	msg_len_g = strlen(msg_gbk);
	len = msg_len_g + SIZE_HEADER + SIZE_MSG_END;
	pheader_smsg[PH_P_LEN] = len;
	header_smsg[P_P_LEN] = len;

	sockfd = socket(AF_INET,SOCK_STREAM,0);										//创建套接字
    if(sockfd == -1){
        perror("socket()");
        exit(EXIT_FAILURE);
    }

	result = connect(sockfd,(struct sockaddr *)&host,sizeof(host));
    if(result == -1){
        perror("connect()");
		close(sockfd);
        exit(EXIT_FAILURE);
    }

	result = write(sockfd,pheader_smsg,SIZE_PHEADER);
    result += write(sockfd,header_smsg,SIZE_HEADER);
	result += write(sockfd,msg_gbk,msg_len_g);
	result += write(sockfd,msg_end,SIZE_MSG_END);
	if(result != (len+SIZE_PHEADER)){
        perror("write()");
        exit(EXIT_FAILURE);
    }
	fprintf(stdout,"msg send to %s:%d, %d Byte\n",argv[2],SERVER_PORT,result);

	free(msg_gbk);
	close(sockfd);
	return (EXIT_SUCCESS);
}
