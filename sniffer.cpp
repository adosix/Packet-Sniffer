#include <iostream>
#include <getopt.h>
#include <string>

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

#define NO_ARGUMENT 0
#define REQUIRED_ARGUMENT 1

using namespace std;

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header)
{
    if(packet_header.caplen != packet_header.len){
        return;
    }
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("%s\n",packet );
    printf("Time: %ld.%06ld\n\n", packet_header.ts.tv_sec, packet_header.ts.tv_usec);
}
void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{
    print_packet_info(packet_body, *packet_header);
    return;
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
    pcap_loop(handle, 0, my_packet_handler, NULL);
}
