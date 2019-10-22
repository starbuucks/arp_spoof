#pragma once

#include <stdint.h>

typedef struct _mac{
	uint8_t i[6];
} MAC;

typedef struct _eth_header{
	MAC dst_mac;
	MAC src_mac;
	uint16_t ether_type;	
} Eth_header;

#pragma pack(1)
typedef struct _arp_headdrer{
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hw_addr_len;
	uint8_t protocol_addr_len;
	uint16_t opcode;
	MAC sender_mac;
	uint32_t sender_addr;
	MAC target_mac;
	uint32_t target_addr;
} ARP_header;

typedef struct _ip_header{
	uint8_t version : 4;
	uint8_t header_len : 4;
	uint8_t tos;
	uint16_t total_len;
	uint16_t identification;
	uint8_t flag : 3;
	uint16_t frag_offset : 13;
	uint32_t src_ip;
	uint32_t dst_ip;
} IP_header;

typedef struct _tcp_header{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t hlen : 4;
	uint8_t reserved : 4;
	uint8_t flag;
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_ptr;
} TCP_header;

int send_arp(const char * dev, MAC s_mac, uint32_t s_ip, MAC t_mac, uint32_t t_ip, int op);
void print_MAC(const char* label, MAC mac);
void print_IP(const char* label, uint32_t ip);
void str_to_ip(char* ip_str, uint32_t* out);