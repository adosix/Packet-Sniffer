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

using namespace std;
struct sockaddr_in source,dest;

int32_t p = -1;             //filter packets on given port (default = all ports)
int n = 1;              // number of packets to display (default = 1) (if n<0 infinite loop)                      
int tcp_f = 0;            //only tcp packets will be shown
int udp_f = 0;            //only udp packets will be shown
int icmp_f = 0;            //only icmp packets will be shown
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0;     //statistics and debug (number of caught packages)

void print_tcp_packet(const u_char *  , int, const struct pcap_pkthdr *);
void print_udp_packet(const u_char *  , int, const struct pcap_pkthdr *);
void print_icmp_packet(const u_char *  , int, const struct pcap_pkthdr *);
char *get_time_from_packet(const struct pcap_pkthdr *header);
void print_data (const u_char * , int);
void list_interfaces();
void my_packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(int argc, char *argv[]){

    string i = "undefined"; //interface (default = all active interfaces)
    
    //processing of arguments
    const struct option longopts[] =
        {
            {"", REQUIRED_ARGUMENT, 0, 'i'},
            {"", REQUIRED_ARGUMENT, 0, 'p'},
            {"tcp", NO_ARGUMENT, 0, 't'},
            {"udp", NO_ARGUMENT, 0, 'u'},
            {"icmp", NO_ARGUMENT, 0, 'c'},
            {"", REQUIRED_ARGUMENT, 0, 'n'},
            {"help", NO_ARGUMENT, 0, 'h'},
        };

    int index;
    int iarg = 0;
    while (iarg != -1){
        iarg = getopt_long(argc, argv, "i:p:tucn:h", longopts, &index);
        switch (iarg){
        case 'i':
            i = optarg;
            break;
        case 'p':
            p = atoi(optarg);
            break;
        case 't':
            tcp_f = 1;
            break;
        case 'u':
            udp_f = 1;
            break;
        case 'c':
            icmp_f = 1;
            break;
        case 'n':
            n = atoi(optarg);
            break;
        case 'h':
            std::cout << "Packet Sniffer" << std::endl;
            std::cout << "Arguments:" << std::endl;
            std::cout << "-i <interface> specifies interface for sniffing" << std::endl;
            std::cout << "-n <number> specifies number of packets to print" << std::endl;
            std::cout << "-p <numebr> specifies port" << std::endl;
            std::cout << "-t/--tcp filters tcp packet" << std::endl;
            std::cout << "-u/--udp filters udp packet" << std::endl;
            std::cout << "-c/--icmp filters icmp packet" << std::endl;
            std::cout << "Examples of usage" << std::endl;
            std::cout << "sudo ./sniffer -i enx00e04c68021d -n 20 -p 443" << std::endl;
            std::cout << "sudo ./sniffer -i enx00e04c68021d -p 443" << std::endl;
            std::cout << "sudo ./sniffer -i enx00e04c68021d -n 20 -t -p 443" << std::endl;
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

    pcap_loop(handle, -1, my_packet_handler, NULL);
}
//lists available interfaces
void list_interfaces(){
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
        exit(1);
    }

    // Query available interfaces
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sck, SIOCGIFCONF, &ifc) < 0)
    {
        perror("error: ioctl(sck, SIOCGIFCONF, &ifc)");
        exit(1);
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
}

//brief: decides which protocol packet had and calls funcion accordingly
void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{
    if(n == 0){
        exit(0);
    }
    int size = packet_header->len;
   

    struct iphdr *iph = (struct iphdr*)(packet_body + sizeof(struct ethhdr));
	++total;
    //Check the Protocol
    //If any filter wasn't applied
    if (tcp_f == 0 && udp_f == 0 && icmp_f == 0)
    {
        switch (iph->protocol) 
        {

            case 1:  //ICMP Protocol
                ++icmp;
                --n;
                print_icmp_packet(packet_body , size, packet_header);
                break;
            
            case 2:  //IGMP Protocol
                ++igmp;
                break;
            
            case 6:  //TCP Protocol
                ++tcp;
                --n;
                print_tcp_packet(packet_body , size, packet_header);
                break;
            case 17: //UDP Protocol
                ++udp;
                --n;
                print_udp_packet(packet_body , size, packet_header);
                break;
            
            default: //Some Other
                //std::cout << "other" << std::endl;
                ++others;
                break;
        }
    }
    else
    {
        switch (iph->protocol) 
        {

            case 1:  //ICMP Protocol
                ++icmp;
                if (icmp_f == 1){
                    --n;
                    print_icmp_packet(packet_body , size, packet_header);
                }
                
                break;
            
            case 2:  //IGMP Protocol
                ++igmp;
                break;
            
            case 6:  //TCP Protocol
                ++tcp;
                if (tcp_f == 1){
                    --n;
                    print_tcp_packet(packet_body , size, packet_header);
                }
                break;
            case 17: //UDP Protocol
                ++udp;
                if (udp_f == 1)
                {
                    --n;
                    print_udp_packet(packet_body , size, packet_header);
                }
                break;
            
            default: //Some Other
                //std::cout << "other" << std::endl;
                ++others;
                break;
        }
    }
//	std::cout << "TCP : "<< tcp  <<" UDP : "<<udp<<" ICMP : " << icmp<<" IGMP : " << igmp <<" Others : "<<others <<" Total : " << total << std::endl;
//	std::cout << "\n-------------------------------------------------------------"<<std::endl;
}

void print_tcp_packet(const u_char * Buffer, int Size, const struct pcap_pkthdr * header){
	unsigned short iphdrlen;
	
    // get ip header
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	//get tcp header
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	if (p != -1 && ((int32_t)ntohs(tcph->source) != p && (int32_t)ntohs(tcph->dest) != p  ))
    {
        if (n!=-1)
        {
            ++n;
        }
        return;
    }		
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	
	std::cout << std::endl << "-------------------TCP Packet-------------------" << std::endl;
    // packet info  
    //time
    char* time = get_time_from_packet(header);
    std::cout << time << "  ";
    //ip adresses
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
    //tryies to get domain name
	hostent * host_src = gethostbyaddr(inet_ntoa(source.sin_addr), strlen(inet_ntoa(source.sin_addr)), AF_INET);
    if(host_src) {
        cout << host_src->h_name ;
    }
    else{
        cout << inet_ntoa(source.sin_addr) ;
    }
    cout << " : "<< ntohs(tcph->source) <<" > ";
    //tryies to get domain name
    hostent * host_dest = gethostbyaddr(inet_ntoa(dest.sin_addr), strlen(inet_ntoa(dest.sin_addr)), AF_INET);
    if(host_dest) {
        cout << host_dest->h_name << std::endl;
    }
    else{
        cout << inet_ntoa(dest.sin_addr) ;
    }
    cout << " : "<< ntohs(tcph->dest) << std::endl;

	print_data(Buffer , Size );
						
}
void print_udp_packet(const u_char *Buffer , int Size, const struct pcap_pkthdr * header){
    
	unsigned short iphdrlen;
	//get ip header
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    if (p != -1 && ((int32_t)ntohs(udph->source) != p && (int32_t)ntohs(udph->dest) != p  ))
    {
        if (n!=-1)
        {
            ++n;
        }
        return;
    }

	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	std::cout << std::endl << "-------------------UDP Packet-------------------" << std::endl;
	// packet info
    //time
    char* time = get_time_from_packet(header);
    std::cout << time << "  ";
    //ip adresses
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
    //tryies to get domain name
	hostent * host_src = gethostbyaddr(inet_ntoa(source.sin_addr), strlen(inet_ntoa(source.sin_addr)), AF_INET);
    if(host_src) {
        cout << host_src->h_name ;
    }
    else{
        cout << inet_ntoa(source.sin_addr) ;
    }
    cout << " : "<< ntohs(udph->source) <<" > ";
    //tryies to get domain name
    hostent * host_dest = gethostbyaddr(inet_ntoa(dest.sin_addr), strlen(inet_ntoa(dest.sin_addr)), AF_INET);
    if(host_dest) {
        cout << host_dest->h_name << std::endl;
    }
    else{
        cout << inet_ntoa(dest.sin_addr) ;
    }
    cout << " : "<< ntohs(udph->dest) << std::endl;
    //packet data		
	print_data(Buffer, Size);
}

void print_icmp_packet(const u_char * Buffer , int Size, const struct pcap_pkthdr * header)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
    if (p != -1 && ((int32_t)ntohs(iph->saddr) != p && (int32_t)ntohs(iph->daddr) != p  )){
        if (n!=-1)
        {
            ++n;
        }
        return;
    }
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
	std::cout << std::endl << "-------------------ICMP Packet-------------------" << std::endl;
	//time
    char* time = get_time_from_packet(header);
    std::cout << time << "  ";
    //ip adresses
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
    //tryies to get domain name
	hostent * host_src = gethostbyaddr(inet_ntoa(source.sin_addr), strlen(inet_ntoa(source.sin_addr)), AF_INET);
    if(host_src) {
        cout << host_src->h_name ;
    }
    else{
        cout << inet_ntoa(source.sin_addr) ;
    }
    cout << " : "<< ntohs(iph->saddr) <<" > ";
    //tryies to get domain name
    hostent * host_dest = gethostbyaddr(inet_ntoa(dest.sin_addr), strlen(inet_ntoa(dest.sin_addr)), AF_INET);
    if(host_dest) {
        cout << host_dest->h_name << std::endl;
    }
    else{
        cout << inet_ntoa(dest.sin_addr) ;
    }
    cout << " : "<< ntohs(iph->daddr) << std::endl;

    
	print_data(Buffer, Size);
	
}
// brief: extract time from packet header and format it
char *get_time_from_packet(const struct pcap_pkthdr *header) {
    struct timeval time_v = header->ts;
    time_t nowtime;
    struct tm *now_time;

    static char time_buff[64], buf[128];
    nowtime = time_v.tv_sec;
    now_time = localtime(&nowtime);

    strftime(time_buff, sizeof time_buff, "%H:%M:%S", now_time);
    snprintf(buf, sizeof buf, "%s.%06ld", time_buff, time_v.tv_usec);
    return buf;
}

// brief: prints content of packet 
//example
//0x0000  B0 BE 76 09 DA 5C 00 E0 4C 68 02 1D 08 00 45 00         ..v..\..Lh....E.
//0x0010  00 34 E5 85 40 00 40 06 87 E9 C0 A8 01 65 28 4D         .4..@.@......e(M
void print_data (const u_char * data , int Size){
	int i , j, n =0;
	for(i=0 ; i < Size ; i++){
        
        if (i==0)
        {
            printf("\n0x%.4d ",n);
        }
        //if line of hex is complete
		if( i!=0 && i%16==0){
			std::cout << "        ";
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
			std::cout << "        ";
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