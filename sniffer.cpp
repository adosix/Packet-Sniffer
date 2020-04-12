#include<iostream>
#include <getopt.h>
#include <string>

#define no_argument 0
#define required_argument 1 

	using namespace std;

	int main(int argc, char* argv[]){
        
        string i = "undefined";  //interface (default = all active interfaces) 
        int p = -1;              //filter packets on given port (default = all ports)
        int tcp = 0;             //only tcp packets will be shown
        int udp = 0;             //only udp packets will be shown
        int n = 1;               // number of packets to display (default = 1)

        const struct option longopts[] =
        {
            {"",   required_argument,        0, 'i'},
            {"",    required_argument,        0, 'p'},
            {"tcp",   no_argument,        0, 't'},
            {"udp",   no_argument,        0, 'u'},
            {"",   required_argument,        0, 'n'},
            {"help",      no_argument,        0, 'h'},
        };


        int index;
        int iarg=0;
        while(iarg != -1)
        {
            iarg = getopt_long(argc, argv, "i:p:tun:h", longopts, &index);

            switch (iarg)
            {
            case 'i':
                i =  optarg;
                break;

            case 'p':
                p =  atoi(optarg);
                break;

            case 't':
                tcp = atoi(optarg);
                break;
                
            case 'u':
                udp =  atoi(optarg);
                break;

            case 'n':
                n =  atoi(optarg);
                break;

            case 'h':
                std::cout << "TODO help" << std::endl;
                break;
            }
        }
        std::cout << i << std::endl;
        std::cout << p << std::endl;
        std::cout << tcp << std::endl;
        std::cout << udp << std::endl;
        std::cout << n << std::endl;
    }