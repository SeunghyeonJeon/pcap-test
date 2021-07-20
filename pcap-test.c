#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>



void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

struct payload {

	uint8_t data[8];

}; 


bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}


void Mac_add_print(struct libnet_ethernet_hdr *eth){
	
	printf("\nDestination Mac : ");
	
	for(int i=0; i<ETHER_ADDR_LEN;i++){
		printf("%02x: ",eth->ether_dhost[i]);
	}	
	printf("\nSource MAC :");


	for(int i=0; i<ETHER_ADDR_LEN;i++){
		printf("%02x ", eth->ether_shost[i]);
	}
}



void Ip_add_print(struct libnet_ipv4_hdr *ip){

	printf("\nSource IP : %s", inet_ntoa(ip->ip_src));
	printf("\nDestination IP : %s", inet_ntoa(ip->ip_dst));

}



void Tcp_port_print(struct libnet_tcp_hdr *tcp){

	printf("\nSource port : %d", ntohs(tcp->th_sport));
	printf("\nDestination port : %d", ntohs(tcp->th_dport));
}



void payload_data_print(struct payload *payload_data){
	
	printf("\nPayload Data : ");

	for(int i=0; i<8;i++){	
		printf("%02x",payload_data->data[i]);
	}

}


int main(int argc, char* argv[]) {
	
	struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr *tcp;
	struct payload *payload_data;


	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}


	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		eth = (struct libnet_ethernet_hdr *) packet;
		ip = (struct libnet_ipv4_hdr *) (packet + sizeof(struct libnet_ethernet_hdr));
		tcp = (struct libnet_tcp_hdr *) (packet + sizeof(struct libnet_ethernet_hdr)+ sizeof(struct libnet_ipv4_hdr));

		payload_data = (struct libnet_tcp_hdr *) (packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
	
		int ether_type = eth->ether_type;
		int ip_p = ip->ip_p;
		int payload_len = ntohs(ip->ip_len) - ((ip->ip_hl)*4+(tcp->th_off)*4);


		if((ether_type == 8)&&(ip_p == 6)){
		printf("========================");
		Mac_add_print(eth);
		printf("\n------------------------");
		Ip_add_print(ip);
		printf("\n------------------------");
		Tcp_port_print(tcp);
		printf("\n------------------------");
		
		if(payload_len == 0)
			printf("\nPayload_data not exists");
		else
			payload_data_print(payload_data);
		
		printf("\n========================\n");
		}
}

	pcap_close(pcap);
}
