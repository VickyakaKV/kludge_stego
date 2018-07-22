#include<stdio.h> 
#include<string.h> 
#include<sys/socket.h>
#include<stdlib.h> 
#include<errno.h> 
#include<netinet/tcp.h>
#include<netinet/ip.h> 
#include<arpa/inet.h>
#include <time.h>
#include <netinet/in.h>
#include <unistd.h>    
#include <pthread.h>
#include <sys/ipc.h>
#include <sys/uio.h>

void error(char *msg){
    perror(msg);
    exit(1);
}

void decode(unsigned char* buffer, int size){
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr*)buffer;
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
    if(iph->protocol == 6){
        char *msg = (char *)malloc(5);
        int seq = tcph->seq;
        int count=0;
        while(count < 4){
            msg[count] = (char)(255 | (seq >> (8 * count)));
        }
        printf("%s", msg);
    }
}

int main(int argc, char *argv[]){

    int sockfd, newsockfd, portno, clilen;
    unsigned char *buffer = (unsigned char *)malloc(65536);
    struct sockaddr_in serv_addr, cli_addr;
    int n;

    if (argc < 2){
        fprintf(stderr,"ERROR, no port provided\n");
        exit(1);
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0){
        error("ERROR opening socket");
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));

    portno = atoi(argv[1]);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){
        error("ERROR on binding");
    }
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd,(struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd < 0){
    error("ERROR on accept");
    }

    bzero(buffer,256);

    n = read(newsockfd,buffer,255);

    if (n < 0){
    error("ERROR reading from socket");
    }

    printf("Here is the message: %s\n",buffer);

    n = write(newsockfd,"I got your message",18);

    if (n < 0){
    error("ERROR writing to socket");
    }
    int s = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    int saddr_size , data_size;
    struct sockaddr saddr;

    while(1){
        saddr_size = sizeof(struct sockaddr);
        //Receive a packet
        data_size = recvfrom(s , buffer , 256 , 0 , (struct sockaddr *)&saddr , &saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        decode(buffer, data_size);
    }
    return 0;
}