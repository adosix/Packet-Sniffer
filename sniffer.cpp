#include <iostream>
#include <getopt.h>
#include <string>
#include <cstdio>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/if_ether.h>

#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>

#define NO_ARGUMENT 0
#define REQUIRED_ARGUMENT 1

FILE *logfile;

using namespace std;

int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0;

void print_tcp_packet(const u_char *  , int );
void PrintData (const u_char * , int);

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{
    int size = packet_header->len;
    struct iphdr *iph = (struct iphdr*)(packet_body + sizeof(struct ethhdr));
	++total;
    //Check the Protocol
	switch (iph->protocol) 
	{
        printf("somthinf");
		case 1:  //ICMP Protocol
			++icmp;
			//print_icmp_packet( packet_body , size);
            printf("icmp");
			break;
		
		case 2:  //IGMP Protocol
			++igmp;
            printf("igmp");
			break;
		
		case 6:  //TCP Protocol
			++tcp;
            printf("tcp");
			print_tcp_packet(packet_body , size);
			break;
		
		case 17: //UDP Protocol
            printf("udp");
			++udp;
			//print_udp_packet(packet_body , size);
			break;
		
		default: //Some Other
            printf("other");
			++others;
			break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);

    //print_packet_info(packet_body, *packet_header);
    //return;
}

int list_interfaces()
{
    char buf[1024];
    struct ifconf ifc;
    struct ifreq *ifr;
    int sck;
    int nInterfaces;
    int i;

    //Get socket handle
    sck = socket(AF_INET, SOCK_DGRAM, 0);
    if (sck < 0)
    {
        perror("error: socket(AF_INET, SOCK_DGRAM, 0)");
        return 1;
    }

    // Query available interfaces
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sck, SIOCGIFCONF, &ifc) < 0)
    {
        perror("error: ioctl(sck, SIOCGIFCONF, &ifc)");
        return 1;
    }

    //Iterate trough list of interfaces
    ifr = ifc.ifc_req;
    nInterfaces = ifc.ifc_len / sizeof(struct ifreq);
    for (i = 0; i < nInterfaces; i++)
    {
        struct ifreq *item = &ifr[i];
        //device name and IP address
        printf("name: %s \r\nIP: %s \r\n",
               item->ifr_name,
               inet_ntoa(((struct sockaddr_in *)&item->ifr_addr)->sin_addr));

        //print BROATCAST
        if (ioctl(sck, SIOCGIFBRDADDR, item) >= 0)
        {
            printf("BROADCAST: %s \r\n\r\n",
                   inet_ntoa(((struct sockaddr_in *)&item->ifr_broadaddr)->sin_addr));
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{

    string i = "undefined"; //interface (default = all active interfaces)
    int p = -1;             //filter packets on given port (default = all ports)
    int tcp = 0;            //only tcp packets will be shown
    int udp = 0;            //only udp packets will be shown
    int n = 1;              // number of packets to display (default = 1)

    const struct option longopts[] =
        {
            {"", REQUIRED_ARGUMENT, 0, 'i'},
            {"", REQUIRED_ARGUMENT, 0, 'p'},
            {"tcp", NO_ARGUMENT, 0, 't'},
            {"udp", NO_ARGUMENT, 0, 'u'},
            {"", REQUIRED_ARGUMENT, 0, 'n'},
            {"help", NO_ARGUMENT, 0, 'h'},
        };

    int index;
    int iarg = 0;
    while (iarg != -1)
    {
        iarg = getopt_long(argc, argv, "i:p:tun:h", longopts, &index);
        switch (iarg)
        {
        case 'i':
            i = optarg;
            break;

        case 'p':
            p = atoi(optarg);
            break;

        case 't':
            tcp = atoi(optarg);
            break;

        case 'u':
            udp = atoi(optarg);
            break;

        case 'n':
            n = atoi(optarg);
            break;

        case 'h':
            std::cout << "TODO help" << std::endl;
            break;
        }
    }
    if (i.compare("undefined") == 0)
    {
        list_interfaces();
    }

    std::cout << p << std::endl;
    std::cout << tcp << std::endl;
    std::cout << udp << std::endl;
    std::cout << n << std::endl;

    const char *device = i.c_str();

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int timeout_limit = 0; /* In milliseconds */

    if (device == NULL)
    {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    /* Open device for live capture */
    handle = pcap_open_live(device, BUFSIZ, 0, timeout_limit, error_buffer);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return 2;
    }
    logfile=fopen("packet_log.txt","w");
    pcap_loop(handle, 5, my_packet_handler, NULL);
}

void print_tcp_packet(const u_char * Buffer, int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	
	printf("\n\n***********************TCP Packet*************************\n");	
		
	printf("\n");
	printf("TCP Header\n");
	printf("   |-Source Port      : %u\n",ntohs(tcph->source));
	printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
	printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	//printf("   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//printf("   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	printf("   |-Window         : %d\n",ntohs(tcph->window));
	printf("   |-Checksum       : %d\n",ntohs(tcph->check));
	printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	printf("\n");
	printf("                        DATA Dump                         ");
	printf("\n");
		
	printf("IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	printf("TCP Header\n");
	PrintData(Buffer+iphdrlen,tcph->doff*4);
		
	printf("Data Payload\n");	
	PrintData(Buffer + header_size , Size - header_size );
						
	printf("\n###########################################################");
}

void PrintData (const u_char * data , int Size)
{
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			printf("         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					printf("%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else printf("."); //otherwise print a dot
			}
			printf("\n");
		} 
		
		if(i%16==0) printf("   ");
			printf(" %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
			  printf("   "); //extra spaces
			}
			
			printf("         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  printf("%c",(unsigned char)data[j]);
				}
				else 
				{
				  printf(".");
				}
			}
			
			printf( "\n" );
		}
	}
}