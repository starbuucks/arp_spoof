#include <unistd.h>  
#include <stdio.h>  
#include <string.h>  
#include <sys/socket.h>  
#include <sys/ioctl.h>  
#include <sys/stat.h>  
#include <netinet/in.h>  
#include <net/if.h>  
#include <arpa/inet.h> 
#include <sys/types.h>

#include "pcap_lib.h"
  
int s_getIpAddress (const char * ifr, unsigned char * out) {  
    // https://tjcplpllog.blogspot.com/2015/02/ip.html
    uint32_t tmp;
    int sockfd;  
    struct ifreq ifrq;  
    struct sockaddr_in * sin;  
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);  
    strcpy(ifrq.ifr_name, ifr);  
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {  
        perror( "ioctl() SIOCGIFADDR error");  
        return -1;  
    }  
    sin = (struct sockaddr_in *)&ifrq.ifr_addr;  
    memcpy (&tmp, (void*)&sin->sin_addr, sizeof(sin->sin_addr));  
    *(uint32_t*)out = ntohl(tmp);

    close(sockfd);  
  
    return 4;  
}  

void mac_eth0(const char * dev, unsigned char * out) {
    // http://community.onion.io/topic/2441/obtain-the-mac-address-in-c-code/3
    #define HWADDR_len 6
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy(out, ifr.ifr_hwaddr.sa_data, 6);
}