#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>

struct route_table_entry *route_table;
int route_table_len;
struct arp_table_entry *arp_table;
int arp_table_len;

void send_icmp_message(char* buf, size_t len, int interface, int type, int code) {
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_header = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
	uint8_t data[64];

	if(type != 0) {
		char *data_ptr = (char *)ip_header + sizeof(struct iphdr);
		memcpy(data, data_ptr, 8);
		icmp_header->un.echo.id = 0;
		icmp_header->un.echo.sequence = 0;
	}

	uint8_t buffer[6];
	memcpy(buffer, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, buffer, 6);
	eth_hdr->ether_type = htons(0x0800);

	uint32_t aux = ip_header->saddr;
	ip_header->saddr = ip_header->daddr;
	ip_header->daddr = aux;
	ip_header->ttl = 64;
	ip_header->check = 0;
	ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);
	ip_header->protocol = IPPROTO_ICMP;
	ip_header->check = htons(checksum((uint16_t *)ip_header, sizeof(struct iphdr)));

	icmp_header->type = type;
	icmp_header->code = code;
	icmp_header->checksum = 0;

	if (type == 3 || type == 11) {
		len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;
		icmp_header->checksum = htons(checksum((uint16_t *)icmp_header, len - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct icmphdr)));
		memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), ip_hdr, sizeof(struct iphdr));
		memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr), data, 8);
    } else {
        icmp_header->checksum = htons(checksum((uint16_t *)icmp_header, len - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct icmphdr)));
    }

	send_to_link(interface, buf, len);
}

int compare(const void *a, const void *b) {
	struct route_table_entry *route1 = (struct route_table_entry *)a;
	struct route_table_entry *route2 = (struct route_table_entry *)b;

	if((route1->prefix & route1->mask) == (route2->prefix & route2->mask))
		return (route1->mask > route2->mask);

	return ((route1->prefix & route1->mask) > (route2->prefix & route2->mask));
}

struct route_table_entry *get_best_route(uint32_t dest)	{

	size_t idx = -1;

    for (size_t i = 0; i < route_table_len; i++)
    {
        if((dest & route_table[i].mask) == route_table[i].prefix)
        {
            if(idx == -1 || (idx != -1 && route_table[i].mask > route_table[idx].mask))
                idx = i;
        }
    }

    if (idx == -1)
        return NULL;

    else
        return &route_table[idx];
}

int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	route_table = (struct route_table_entry*)malloc(1000000 * sizeof(struct route_table_entry));
    DIE(route_table == NULL, "memory");
	route_table_len = read_rtable(argv[1], route_table);
	qsort(route_table, route_table_len, sizeof(struct route_table_entry), compare);

	arp_table = (struct arp_table_entry*)malloc(1000000 * sizeof(struct arp_table_entry));
	DIE(arp_table == NULL, "memory");
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1) {

		int interface;
        size_t len;
        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");
        struct ether_header *eth_hdr = (struct ether_header *)buf;

		if(ntohs(eth_hdr->ether_type) == 0x0800) {
			struct iphdr *ip_header = (struct iphdr*)(buf + sizeof(struct ether_header));

			uint16_t old_sum = ip_header->check;
        	ip_header->check = 0;
        	if (htons(checksum((uint16_t *)ip_header, ntohs(ip_header->tot_len))) != old_sum) {
            	continue;
        	}

			if(ip_header->ttl == 0 || ip_header->ttl == 1)	{
				send_icmp_message(buf, len, interface, 11, 0);
            	continue;
        	}
			ip_header->ttl--;

			if (ip_header->daddr == inet_addr(get_interface_ip(interface))) {
				send_icmp_message(buf, len, interface, 0, 0);
				continue;
			}

			struct route_table_entry *rtable_best = get_best_route(ip_header->daddr);
        	if(rtable_best == NULL)	{
				send_icmp_message(buf, len, interface, 3, 0);
            	continue;
       		}

        	ip_header->check = htons(checksum((uint16_t *)ip_header, ntohs(ip_header->tot_len)));  
		
        	struct arp_table_entry *searched_arp = NULL;
			for(int i = 0; i < arp_table_len; i++) {
				if(arp_table[i].ip == rtable_best->next_hop) {
					searched_arp = &arp_table[i];
					break;
				}
			}

			if(searched_arp == NULL) {
        		continue;
        	}
			
			uint8_t mac_s[6];
			get_interface_mac(rtable_best->interface, mac_s);

			memcpy(eth_hdr->ether_shost, mac_s, 6);
			memcpy(eth_hdr->ether_dhost, searched_arp->mac, 6);
			eth_hdr->ether_type = htons(0x0800);

			printf("Packet eth shost : %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
			printf("Packet eth dhost : %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
			
        	send_to_link(rtable_best->interface, buf, len);
		}
	}
}