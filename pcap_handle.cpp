#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <map>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include "pcap_handle.h"

using namespace std;

int get_mac(const char * dev, pcap_t * handle, const uint32_t my_ip, const MAC my_mac, uint32_t ip, MAC * mac){

	// broadcast arp request
	MAC broadcast;
	memset(&broadcast, '\xFF', 6);
	send_arp(dev, my_mac, my_ip, broadcast, ip, ARPOP_REQUEST);

	// wait for the response
	ARP_header * arp_pkt;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		if(ntohs(((Eth_header*)packet)->ether_type) != ETHERTYPE_ARP) continue;
		arp_pkt = (ARP_header*)(packet + 0xE);

		if(ntohl(arp_pkt->sender_addr) == ip && ntohs(arp_pkt->opcode) == ARPOP_REPLY) break;
	}
	memcpy(mac, &(arp_pkt->sender_mac), 6);

	return 0;
}

int send_arp(const char * dev, MAC s_mac, uint32_t s_ip, MAC t_mac, uint32_t t_ip, int op){

	printf("send arp ");

	// make ARP packet
	int packet_len = sizeof(Eth_header) + sizeof(ARP_header);
	u_char* packet = (u_char*)malloc(packet_len);

	// build ethernet header
	Eth_header eth;
	memcpy(&(eth.dst_mac), &t_mac, 6);
	memcpy(&(eth.src_mac), &s_mac, 6);
	eth.ether_type = htons(ETHERTYPE_ARP);

	// build ARP header
	ARP_header arp;
	arp.hardware_type = htons(1);
	arp.protocol_type = htons(0x0800);
	arp.hw_addr_len = 6;
	arp.protocol_addr_len = 4;
	arp.opcode = htons(op);
	memcpy(&(arp.sender_mac), &s_mac, 6);
	arp.sender_addr = htonl(s_ip);
	if(op == ARPOP_REQUEST)
		memset(&(arp.target_mac), 0, 6);
	else
		memcpy(&(arp.target_mac), &t_mac, 6);
	arp.target_addr = htonl(t_ip);

	// copy headers to the packet
	memcpy(packet, &eth, sizeof(Eth_header));
	memcpy(packet + sizeof(Eth_header), &arp, sizeof(ARP_header));

	// send packet (https://blog.pages.kr/290)
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *fp;
	fp = pcap_open_live(dev, 65536, 0, 1000, errbuf);
	int e=pcap_sendpacket(fp, packet, packet_len);

	return 0;
}

void send_arp_frequently(int frequency, vector<Session> s_list, map<uint32_t, MAC> mac_map, const char * dev, MAC my_mac){

	while(1){
		for(vector<Session>::iterator it = s_list.begin();
			it != s_list.end();
			it++)
			send_arp(dev, my_mac, it->target_ip, mac_map[it->sender_ip], it->sender_ip, ARPOP_REPLY);

		sleep(frequency);
	}
}

void print_MAC(const char* label, MAC mac){
	printf("%s : %02X:%02X:%02X:%02X:%02X:%02X\n", label,
		mac.i[0], mac.i[1], mac.i[2], mac.i[3], mac.i[4], mac.i[5]);
}

void print_IP(const char* label, uint32_t ip){
	printf("%s : %d.%d.%d.%d\n", label,
		(ip & 0xFF000000) >> 24,
		(ip & 0x00FF0000) >> 16,
		(ip & 0x0000FF00) >> 8,
		(ip & 0x000000FF));
}

void str_to_ip(char* ip_str, uint32_t* out){
	int i, st;
	int j = -1;
	uint8_t ip_arr[4];
	for(i = 0; i < 4; i++){
		st = ++j;
		for(; ip_str[j] != '.' && ip_str[j] != '\x00'; j++);
		ip_str[j] = '\x00';
		ip_arr[3 - i] = atoi(ip_str + st);
	}
	memcpy(out, ip_arr, 4);
}
