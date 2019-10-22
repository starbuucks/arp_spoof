all : arp_spoof

arp_spoof: main.o pcap_lib.o pcap_handle.o
	g++ -g -o arp_spoof pcap_lib.o pcap_handle.o main.o -lpcap -lpthread

pcap_lib.o: pcap_lib.cpp pcap_lib.h
	g++ -g -c -o pcap_lib.o pcap_lib.cpp

pcap_handle.o: pcap_handle.cpp pcap_handle.h
	g++ -g -c -o pcap_handle.o pcap_handle.cpp

main.o: main.cpp pcap_lib.h pcap_handle.h
	g++ -g -c -o main.o main.cpp

clean:
	rm -f arp_spoof
	rm -f *.o

