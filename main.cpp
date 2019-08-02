#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>

void usage();
void get_target_MAC(pcap_t* fp, const uint8_t* sender_MAC, const uint8_t* sender_IP, const uint8_t* target_IP);
void get_my_MAC(u_char* mymac);
void get_MAC();
void arp_poison();

int main(int argc, char** argv)
{
    if (argc != 4)
    {             // Check argument.
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev_list = pcap_lookupdev(errbuf);

    uint32_t sender_ip_tmp = inet_addr(argv[2]);
    uint8_t sender_ip[4];
    memcpy(sender_ip, &sender_ip_tmp, 32);

    uint32_t target_ip_tmp = inet_addr(argv[3]);
    uint8_t target_ip[4];
    memcpy(target_ip, &target_ip_tmp, 32);

    pcap_t* handle = pcap_open_live(dev, 42, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }


    uint8_t host_mac[6];
    get_my_MAC(host_mac);
    get_target_MAC(handle, host_mac, sender_ip, target_ip);

    return 0;
}

void usage()
{
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

void get_my_MAC(uint8_t* mymac)
{
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, "eth0");
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s))
    {
        int i;
        for (i = 0; i < 6; ++i)
        {
            printf(" %02x", static_cast<unsigned char>(s.ifr_addr.sa_data[i]));
            mymac[i] = static_cast<unsigned char>(s.ifr_addr.sa_data[i]);
        }
        puts("\n");
    }
}

void get_target_MAC(pcap_t* fp, const uint8_t* sender_MAC, const uint8_t* sender_IP, const uint8_t* target_IP)
{
    u_char arp_packet[42];

    ethhdr eth_hdr;                             //defined <linux/if_ether.h>
    for (int i=0;i<6;i++)
    {
        eth_hdr.h_dest[i] = 0xff;   //Set broadcast MAC
        eth_hdr.h_source[i] = sender_MAC[i];   //Set source MAC
    }
    eth_hdr.h_proto = htons(ETH_P_ARP);

    ether_arp arp_hdr;
    arp_hdr.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr.ea_hdr.ar_pro = htons(0x0800);
    arp_hdr.ea_hdr.ar_hln = 0x06;
    arp_hdr.ea_hdr.ar_pln = 0x04;
    arp_hdr.ea_hdr.ar_op = htons(ARPOP_REQUEST);  // 1
    for (int i=0;i<6;i++)
    {
        arp_hdr.arp_sha[i] = sender_MAC[i];
        arp_hdr.arp_tha[i] = 0x00;
    }

    for (int i = 0; i < 4; i++)
    {
        arp_hdr.arp_spa[i] = sender_IP[i];
        arp_hdr.arp_tpa[i] = target_IP[i];
    }
    memcpy(arp_packet, &eth_hdr, sizeof(ethhdr));
    memcpy(&arp_packet[sizeof(ethhdr)], &arp_hdr, sizeof(arp_hdr));
    if((pcap_sendpacket(fp, arp_packet, sizeof(arp_packet))) != 0)
    {
        fprintf(stderr, "\nSending ARP_Request Failed");
    }
    else
    {
        while (true)
        {
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(fp, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
            printf("==============================================\n");
            printf("%u bytes captured\n", header->caplen);
            for (int i = 0; i < 42; i++)
            {
                printf("%02X", packet[i]);
            }
             printf("==============================================\n");
        }
    }
}
