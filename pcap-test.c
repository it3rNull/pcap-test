#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdbool.h>
#include "headers.h"
int ether_type(const u_char *packet);
int ip_protocol(const u_char *packet, ip_hdr *ipinfo);
void ether_info(const u_char *packet);
int ip_info(ip_hdr *ipinfo);
void tcp_info(const u_char *packet, ip_hdr *ipinfo);

void usage()
{
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{
    if (argc != 2)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char *argv[])
{
    ether_hdr eth;

    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        ip_hdr ipinfo;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        if (ether_type(packet))
        {
            if (ip_protocol(packet + 14, &ipinfo))
            {
                ether_info(packet);
                ip_info(&ipinfo);
                tcp_info(packet + 14 + 4 * (ipinfo.ip_hl), &ipinfo);
            }
        }
    }

    pcap_close(pcap);
}

int ether_type(const u_char *packet)
{
    ether_hdr *e_hdr;
    e_hdr = (ether_hdr *)packet;
    u_int16_t type = ntohs(e_hdr->ether_type);
    if (type == 0x800)
    {
        return 1;
    }
    else if (type != 0x800)
    {
        return 0;
    }
}

int ip_protocol(const u_char *packet, ip_hdr *ipinfo)
{
    ip_hdr *ip4_hdr;
    ip4_hdr = (ip_hdr *)packet;
    ipinfo->ip_source = ip4_hdr->ip_source;
    ipinfo->ip_dest = ip4_hdr->ip_dest;
    ipinfo->ip_hl = ip4_hdr->ip_hl;
    ipinfo->ip_len = ip4_hdr->ip_len;
    if (ip4_hdr->ip_protocol == 6)
    {
        return 1;
    }
    else if (ip4_hdr->ip_protocol != 6)
    {
        return 0;
    }
}
void ether_info(const u_char *packet)
{
    ether_hdr *e_hdr;
    e_hdr = (ether_hdr *)packet;
    printf("=============Ethernet header=============\n");
    printf("dest mac : ");
    for (int i = 0; i < 6; i++)
    {
        printf("%02x", e_hdr->ether_dest[i]);
        if (i < 5)
        {
            printf(":");
        }
    }
    printf("\n");
    printf("source mac : ");
    for (int i = 0; i < 6; i++)
    {
        printf("%02x", e_hdr->ether_source[i]);
        if (i < 5)
        {
            printf(":");
        }
    }
    printf("\n");
}

int ip_info(ip_hdr *ipinfo)
{
    printf("===============IPv4 header===============\n");
    printf("source IP address : ");
    u_int8_t *src = (u_int8_t *)&(ipinfo->ip_source);
    u_int8_t *dst = (u_int8_t *)&(ipinfo->ip_dest);
    for (int i = 0; i < 4; i++)
    {
        printf("%d", *(src + i));
        if (i < 3)
        {
            printf(".");
        }
    }
    printf("\n");
    printf("destination IP address : ");
    for (int i = 0; i < 4; i++)
    {
        printf("%d", *(dst + i));
        if (i < 3)
        {
            printf(".");
        }
    }
    printf("\n");
}

void tcp_info(const u_char *packet, ip_hdr *ipinfo)
{
    tcp_hdr *t_hdr;
    t_hdr = (tcp_hdr *)packet;
    const u_char *payload = packet + 4 * (t_hdr->tcp_offset);
    u_int16_t length = ntohs(ipinfo->ip_len);
    printf("total length : %d\n", length);
    printf("hl : %d , tcp : %d\n", ipinfo->ip_hl, t_hdr->tcp_offset);
    length -= 4 * (ipinfo->ip_hl + t_hdr->tcp_offset);
    printf("payload length : %d\n", length);
    printf("===============TCP header===============\n");
    printf("TCP source port : ");
    printf("%d\n", ntohs(t_hdr->tcp_source));
    printf("TCP dest port : ");
    printf("%d\n", ntohs(t_hdr->tcp_dest));

    if (length < 10)
    {
        for (int i = 0; i < length; i++)
        {
            printf("%02x ", payload[i]);
        }
        printf("\n");
    }
    else if (length >= 10)
    {
        for (int i = 0; i < 10; i++)
        {
            printf("%02x ", payload[i]);
        }
        printf("\n");
    }
}