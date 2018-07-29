#include <pcap.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#define ARP 0x608
#define IPv4 0x08
#define IPv6 0xdd08
#define ICMP 1
#define TCP 6
#define UDP 17
void ether_type(int t){

	switch(t){

		case ARP:
			printf("ETHERTYPE:	 ARP\n");
			break;
		
		case IPv4:
			printf("ETHERTYPE:	 IPv4\n");
			break;

		case IPv6:
			printf("ETHERTYPE:	 IPv6\n");
			break;
	
		deafault:
			printf("ETHERTYPE:	 0x%x\n",t);
			break;

	}
}

void ip_protocol(int p){

	switch(p){

		case ICMP:
			printf("IP Protocol: 	 ICMP\n");
			break;
		 
		case TCP:
			printf("IP Protocol: 	 TCP\n");
			break;
		case UDP:
			printf("IP Protocol: 	 TCP\n");
			break;
		default:
			printf("IP Protocol: 	 %d\n",p);
			break;

	}
}

void usage() {

	printf("syntax: pcap_test <interface>\n");
  	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  	if (argc != 2) {
   		 usage();
    		return -1;
  	}
	struct ether_header *ether;
	struct ip *ip;
	struct tcphdr *tcp;
  	char* dev = argv[1];
  	char errbuf[PCAP_ERRBUF_SIZE];
  	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  	if (handle == NULL) {
  	
		  fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
  		  return -1;
  	
	}

  	while (true) {
   
		struct pcap_pkthdr* header;
    		const u_char* packet;
    		int res = pcap_next_ex(handle, &header, &packet);
    		if (res == 0) continue;
   		if (res == -1 || res == -2) break;
		ether = (struct ether_header *)packet;
		packet+=sizeof(struct ether_header); // offset


		printf("\nDestination Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",ether->ether_dhost[0],ether->ether_dhost[1],ether->ether_dhost[2],ether->ether_dhost[3],ether->ether_dhost[4],ether->ether_dhost[5]);
		printf("Source Mac:	 %02x:%02x:%02x:%02x:%02x:%02x\n",ether->ether_shost[0],ether->ether_shost[1],ether->ether_shost[2],ether->ether_shost[3],ether->ether_shost[4],ether->ether_shost[5]);
		ether_type(ether->ether_type);
		//printf("%x",ether->ether_type);
		
		if(ether->ether_type != 8)continue;

		ip=(struct ip *)packet;
		printf("IP Version: 	 %d\n",ip->ip_v);	
		printf("Destination Ip:	 %s\n",inet_ntoa(ip->ip_dst));
		printf("Source Ip:	 %s\n",inet_ntoa(ip->ip_src));
		ip_protocol(ip->ip_p);	
		packet+=ip->ip_hl*4;	// offset	>>	packet+=header length*4

		if(ip->ip_p != 6) {printf("\n"); continue;}

		tcp=(struct tcphdr *)packet;
		packet+=tcp->th_off*4;
		printf("Destination Port: %d\n",htons(tcp->th_dport));
		printf("Source Port: 	  %d\n",htons(tcp->th_sport));
		printf("-------------Data--------------\n");
		for(int i=0; i< 16;i++){
		
			printf("%c",packet[i]);

		}
			printf("\n");
		printf("--------------------------------\n\n\n");
	

		
	
  }

  pcap_close(handle);
  return 0;
}
