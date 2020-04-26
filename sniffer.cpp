#include <iostream>
#include <getopt.h>
#include <string>
#include <cstdio>
#include <cstring>

#include <net/if.h>
#include <sys/ioctl.h>
#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#define NO_ARGUMENT 0
#define REQUIRED_ARGUMENT 1

FILE *logfile;

using namespace std;
struct sockaddr_in source,dest;

int p = -1;             //filter packets on given port (default = all ports)
int tcp = 0;            //only tcp packets will be shown
int udp = 0;            //only udp packets will be shown

int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0;     //statistics and debug (number of caught packages)

void print_tcp_packet(const u_char *  , int, const struct pcap_pkthdr *);
void print_udp_packet(const u_char *  , int, const struct pcap_pkthdr *);
void print_icmp_packet(const u_char *  , int, const struct pcap_pkthdr *);
char *get_time_from_packet(const struct pcap_pkthdr *header);
void PrintData (const u_char * , int);
int list_interfaces();
void my_packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(int argc, char *argv[]){

    string i = "undefined"; //interface (default = all active interfaces)
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
    while (iarg != -1){
        iarg = getopt_long(argc, argv, "i:p:tun:h", longopts, &index);
        switch (iarg){
        case 'i':
            i = optarg;
            break;
        case 'p':
            p = atoi(optarg);
            break;
        case 't':
            tcp = 1;
            break;
        case 'u':
            udp = 1;
            break;
        case 'n':
            n = atoi(optarg);
            break;
        case 'h':
            std::cout << "TODO help" << std::endl;
            break;
        }
    }
    if (i.compare("undefined") == 0){
        list_interfaces();
    }
    const char *device = i.c_str();

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int timeout_limit = 0; /* In milliseconds */

    if (device == NULL){
        std::cout << "Error finding device: " << error_buffer << std::endl;
        return 1;
    }

    /* Open device for live capture */
    handle = pcap_open_live(device, BUFSIZ, 0, timeout_limit, error_buffer);
    if (handle == NULL){
        std::cerr << "Could not open device "<< device<< " : " <<error_buffer << std::endl;
        return 2;
    }
    logfile=fopen("packet_log.txt","w");

    pcap_loop(handle, n, my_packet_handler, NULL);
}

int list_interfaces(){
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

    // get available interfaces
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
        std::cout << "name: "<< item->ifr_name << " IP: " << inet_ntoa(((struct sockaddr_in *)&item->ifr_addr)->sin_addr) << std::endl;

        if (ioctl(sck, SIOCGIFBRDADDR, item) >= 0)
        {
            std::cout << "BROADCAST: " << inet_ntoa(((struct sockaddr_in *)&item->ifr_broadaddr)->sin_addr) << std::endl << std::endl;
        }
    }
    return 0;
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{
    int size = packet_header->len;
   

    struct iphdr *iph = (struct iphdr*)(packet_body + sizeof(struct ethhdr));
	++total;
    //Check the Protocol
	switch (iph->protocol) 
	{

		case 1:  //ICMP Protocol
			++icmp;
			print_icmp_packet(packet_body , size, packet_header);
			break;
		
		case 2:  //IGMP Protocol
			++igmp;
			break;
		
		case 6:  //TCP Protocol
			++tcp;
			print_tcp_packet(packet_body , size, packet_header);
			break;
		case 17: //UDP Protocol
			++udp;
			print_udp_packet(packet_body , size, packet_header);
			break;
		
		default: //Some Other
            //std::cout << "other" << std::endl;
			++others;
			break;
	}
	std::cout << "TCP : "<< tcp  <<" UDP : "<<udp<<" ICMP : " << icmp<<" IGMP : " << igmp <<" Others : "<<others <<" Total : " << total << std::endl;

	//std::cout << "\n-------------------------------------------------------------"<<std::endl;
    
}



void print_tcp_packet(const u_char * Buffer, int Size, const struct pcap_pkthdr * header){
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	
	std::cout << std::endl << "-------------------TCP Packet-------------------" << std::endl;
    // packet info  
    //time
    char* time = get_time_from_packet(header);
    printf("%s ", time);
    //ip adresses
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	hostent * host_src = gethostbyaddr(inet_ntoa(source.sin_addr), strlen(inet_ntoa(source.sin_addr)), AF_INET);
    if(host_src) {
        cout << host_src->h_name ;
    }
    else{
        cout << inet_ntoa(source.sin_addr) ;
    }
    cout << " : "<< ntohs(tcph->source) <<" > ";

    hostent * host_dest = gethostbyaddr(inet_ntoa(dest.sin_addr), strlen(inet_ntoa(dest.sin_addr)), AF_INET);
    if(host_dest) {
        cout << host_dest->h_name << std::endl;
    }
    else{
        cout << inet_ntoa(dest.sin_addr) ;
    }
    cout << " : "<< ntohs(tcph->dest) << std::endl;

	PrintData(Buffer , Size );
						
}
void print_udp_packet(const u_char *Buffer , int Size, const struct pcap_pkthdr * header){
	
    
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	std::cout << std::endl << "-------------------UDP Packet-------------------" << std::endl;
	// packet info
    //time
     
    printf("%d.%06d",
		(int) header->ts.tv_sec, (int) header->ts.tv_usec);

    //ip adresses
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	hostent * host_src = gethostbyaddr(inet_ntoa(source.sin_addr), strlen(inet_ntoa(source.sin_addr)), AF_INET);
    if(host_src) {
        cout << host_src->h_name ;
    }
    else{
        cout << inet_ntoa(source.sin_addr) ;
    }
    cout << " : "<< ntohs(udph->source) <<" > ";

    hostent * host_dest = gethostbyaddr(inet_ntoa(dest.sin_addr), strlen(inet_ntoa(dest.sin_addr)), AF_INET);
    if(host_dest) {
        cout << host_dest->h_name << std::endl;
    }
    else{
        cout << inet_ntoa(dest.sin_addr) ;
    }
    cout << " : "<< ntohs(udph->dest) << std::endl;
    //packet data		
	PrintData(Buffer, Size);
}

void print_icmp_packet(const u_char * Buffer , int Size, const struct pcap_pkthdr * header)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
	std::cout << std::endl << "-------------------ICMP Packet-------------------" << std::endl;
	//time
    printf("%d.%06d  ",
		(int) header->ts.tv_sec, (int) header->ts.tv_usec);
    //ip adresses
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	hostent * host_src = gethostbyaddr(inet_ntoa(source.sin_addr), strlen(inet_ntoa(source.sin_addr)), AF_INET);
    if(host_src) {
        cout << host_src->h_name ;
    }
    else{
        cout << inet_ntoa(source.sin_addr) ;
    }
    cout << " : "<< ntohs(iph->saddr) <<" > ";

    hostent * host_dest = gethostbyaddr(inet_ntoa(dest.sin_addr), strlen(inet_ntoa(dest.sin_addr)), AF_INET);
    if(host_dest) {
        cout << host_dest->h_name << std::endl;
    }
    else{
        cout << inet_ntoa(dest.sin_addr) ;
    }
    cout << " : "<< ntohs(iph->daddr) << std::endl;

    
	PrintData(Buffer, Size);
	
}

char *get_time_from_packet(const struct pcap_pkthdr *header) {
    time_t time;
    struct tm *tm;
    static char tbuf[64], buf[64];
    struct timeval tv = header->ts;
    time = tv.tv_sec;
    tm = localtime(&time);

    strftime(tbuf, sizeof tbuf, "%h:%h:%S", tm);
    snprintf(buf, sizeof buf, "%s.%06ld", tbuf, tv.tv_usec);

    return buf;
}


void PrintData (const u_char * data , int Size){
	int i , j, n =0;
	for(i=0 ; i < Size ; i++){
        
        if (i==0)
        {
            printf("\n0x%.4d ",n);
        }
        
        
        //if line of hex is complete
		if( i!=0 && i%16==0){
			std::cout << "         ";
			for(j=i-16 ; j<i ; j++){
				if(data[j]>=32 && data[j]<=128)
					std::cout << (unsigned char)data[j]; //if its a number or alphabet
				
				else std::cout << "."; //otherwise print a dot
			}
            n=n+10;
            std::cout <<std::endl;
            printf( "0x%.4d ",n);
		}

        printf( " %02X",(unsigned int)data[i]);
		//last spaces
		if( i==Size-1){
			for(j=0;j<15-i%16;j++){
			  std::cout << "   ";
			}
			std::cout << "         ";
			for(j=i-i%16 ; j<=i ; j++){
				if(data[j]>=32 && data[j]<=128){
				  std::cout << (unsigned char)data[j];
				}
				else{
				  std::cout << ".";
				}
			}
			
			std::cout << std::endl;
		}
        
	}
}