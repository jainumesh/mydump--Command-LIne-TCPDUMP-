#include "mydump.h"

/*Using  some global variables for easy communication :)*/
/*Bad practice but...............*/
char * spdevice_name;
char * filename;
char * _string;
char * _expressions;
pcap_t* phndlr;
char errbuf[BUFFSIZE];


int main(int argc ,char* argv[])
{
	int counter_i = 1;
	bpf_u_int32 mask = 0; // Defining as per LibPcap
	bpf_u_int32 net = 0;  // Defining as per LibPcap
	struct bpf_program fp; // Filter expression "BPF"
	int read_from_file = 0;// if -r option is used
	FILE * filep; 			 // PCAP File to read input from

	/*Parse the command line options 1st,
	we only support '-i' , '-s' and '-r' for this exercise :D */
	/*Also if -i and -r are both present, -r takes precedence */
	while(argc>counter_i)
	{
		if(argv[counter_i][0] == '-'){
			
			switch(argv[counter_i][1]){
				case 'i':
					spdevice_name = argv[counter_i+1];
					break;
				case 'r':
					filename = argv[counter_i+1];
					read_from_file = 1;
					break;
				case 's':
					_string = argv[counter_i+1];
					break;
				default:
					fprintf(stdout,"UNSUPPORTED INPUT \n");
					fprintf(stdout, "USAGE  Directions:\nmydump [-i interface] [-r file] [-s string]  expression\n");
					fprintf(stdout,"Please re Run the program/command :)\n");
					return ERR_RETURN;
				}
			counter_i+=2;
		}else{
		_expressions = argv[counter_i++];
		break;
		}
	}
	if(read_from_file){
		filep = fopen(filename,"rb");
		if(NULL == filep){
			fprintf(stdout,"Failed to open the file\n");
			return 0;
		}
		phndlr = pcap_fopen_offline(filep,errbuf);
		if(NULL == phndlr){
			fprintf(stdout,"failed to capture with error [%s]\n", errbuf);
			return ERR_RETURN;
		}
		
	}else{

		if(spdevice_name == NULL){
			spdevice_name  = pcap_lookupdev(errbuf);
			fprintf(stdout,"No input for device to capture, defaulting to [%s]\n",spdevice_name);
		}else if(pcap_lookupnet(spdevice_name,&net,&mask,errbuf) == -1){
					fprintf(stdout,"device lookup for [%s] failed\n", spdevice_name);
					fprintf(stdout,"Exiting");
					return ERR_RETURN;
		}
		open_pcap();

	}
		 if(NULL != _expressions && ERR_RETURN != compile_filter(&fp,net)){
			if(ERR_RETURN == set_filter(&fp))
				return  ERR_RETURN;
		 }
		pcap_loop(phndlr,-1,got_packet, _string);
			
		
		//pcap_freecode(&fp);
		pcap_close(phndlr);
		fprintf(stdout,"\n\n==========END of CAPTURE=============\n\n");

}

/*If user does live packet capture by specifying an interface, open it.*/
int open_pcap(){
    phndlr = pcap_open_live(spdevice_name,BUFSIZ,1,0,errbuf);
    if(NULL == phndlr){
        fprintf(stdout,"failed to capture with error [%s]\n", errbuf);
        return ERR_RETURN;
    }

}
/*Compile the BPF filter for packet capture. Yes this is needed by the pcap lib*/
int compile_filter(struct bpf_program *fp,bpf_u_int32 net){



    if(ERR_RETURN == pcap_compile(phndlr,fp,_expressions,0,net)){
        fprintf(stdout,"Couldn't parse filter %s: %s\n", _expressions, pcap_geterr(phndlr));
        return ERR_RETURN;
    }

}

/*Set the BPF filter for packet capture*/
int set_filter(struct bpf_program *fp){

    if(ERR_RETURN == pcap_setfilter(phndlr,fp)){
        fprintf(stdout,"Couldn't install filter %s: %s\n", _expressions, pcap_geterr(phndlr));
        return ERR_RETURN;
    }

}

/*This API checks if the application layer payload can be 
 * represented as character if, yes it replaces with character ,else with a dot '.'*/
void convert_payload_to_string(const u_char * payload,char * payload_printable,int payload_size)
{	
const unsigned char *ch = payload;
unsigned char *ch2 = payload_printable;
int i=0;

for(;i<payload_size;i++){
	if(isprint(*ch))
		*ch2 = *ch;
	else
		*ch2 = '.';	
	ch++;
	ch2++;
}
	*ch2 = '\0';
return;
}

/*Callback Function received from pcap Library*/
/*Pcap lib calls this callback everytime it receives a packet*/
/*This Function is the key , it will print per packet data as needed in problem statement*/

void got_packet(u_char *pattern, const struct pcap_pkthdr *header,const u_char *packet)
{
	/* Too many variables, keep each tracked*/
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const struct sniff_udp *udp; /* The TCP header */
    const unsigned char *payload; /* Packet payload */
    unsigned char *payload_printable; /* Packet payload */
	char *s;						  /*temp string for multipurpose usage*/	
	char protocol_name[5] = {"\0"};	  /*TCP,UDP,ARP,ICMP etc..*/ 	
    u_int size_ip;					 /*IP Heade Sizer*/
    u_int size_proto;				  /*Transport layer protocol size(UDP or TCP)*/
	int payload_size;				  /*Application layer packet size(HTTP etc)*/	
	int i = 0;
	int k = 0;
	int l = 0;
	
	/*check for bad input*/
    if(NULL == packet || NULL == header)
        return;

ethernet = (struct sniff_ethernet*)(packet);

ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
size_ip = IP_HL(ip)*4;
if (size_ip < 20) {
    fprintf(stdout,"   * Invalid IP header length: %u bytes\n", size_ip);
    return;
}
/*If a TCP packet*/
if(ip->ip_p == IPPROTO_TCP){
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_proto = TH_OFF(tcp)*4;
		strncpy(protocol_name,"TCP\0",4);
}
/*If a UDP packet*/
else{ 
	if(ip->ip_p == IPPROTO_UDP){
		size_proto = 8;	
		strncpy(protocol_name,"UDP\0",4);
	}
/*If a ICMP packet*/
	else{ 
		if(ip->ip_p == IPPROTO_ICMP){
			size_proto = 8;	
			strncpy(protocol_name,"ICMP\0",5);
		}
	}
}
/*size of whole payload*/
payload_size = ntohs(ip->ip_len)%MSS - size_ip + size_proto;

/*point to the application layer payload*/
payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_proto);

/*Need printable version of application layer data as well */
payload_printable = (u_char *)malloc(payload_size+1);
convert_payload_to_string(payload,payload_printable,payload_size);

/*check if user specified '-s' option, if yes, filter as per the string provided*/
if(pattern !=NULL && 0 == strstr(payload_printable,pattern)){
	return;	
}

/*Add code to print the details as needed in Question*/    

/*Print Time*/
s = ctime((const time_t*)&header->ts);
s[strlen(s)-1] = '\0';
fprintf(stdout, "%s ",s);

/*Print Eth Headers*/
fprintf(stdout,"%x:%x:%x:%x:%x:%x",ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
fprintf(stdout," -> ");	
fprintf(stdout,"%x:%x:%x:%x:%x:%x",ethernet->ether_shost[0],ethernet->ether_shost[1],\
	ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);

/*print type*/
fprintf(stdout," type 0x%x00 ",ethernet->ether_type);

/*print Length*/
fprintf(stdout,"len %d",ntohs(ip->ip_len)+ size_ip +SIZE_ETHERNET);

/*Print IP Addresses*/
s = (char*)inet_ntoa(ip->ip_src);
fprintf(stdout," %s ",s);
s = (char*)inet_ntoa(ip->ip_dst);
fprintf(stdout," %s  %s\n",s,protocol_name);

/*Now the messy part: Print the DATA as Hex and String 
 * in 16 entries per line (TCPDUMP does it ike this)*/
for(i=0;i<=payload_size;i=i+16)
{	k = payload_size - i;
	if(k>=16){
		fprintf(stdout,"%02x %02x %02x %02x ",payload[i+0],payload[i+1],payload[i+2],payload[i+3]);
		fprintf(stdout,"%02x %02x %02x %02x ",payload[i+4],payload[i+5],payload[i+6],payload[i+7]);
		fprintf(stdout,"%02x %02x %02x %02x ",payload[i+8],payload[i+9],payload[i+10],payload[i+11]);
		fprintf(stdout,"%02x %02x %02x %02x       ",payload[i+12],payload[i+13],payload[i+14],payload[i+15]);
		for(k=0;k<16;k++)
			fprintf(stdout,"%c",payload_printable[i+k]);
		fprintf(stdout,"\n");
	}else{
			int gap = k;
			for(l=0;l<k;l++)
				fprintf(stdout,"%02x ",payload[i+l]);	
			for(;k<16;k++)
				fprintf(stdout,"   ");
			fprintf(stdout,"      ");	
			k = gap;
			for(l=0;l<k;l++)
				fprintf(stdout,"%c ",payload_printable[i+l]);	
			for(;k<16;k++)
				fprintf(stdout," ");	
			fprintf(stdout,"\n");
			
		}
}	

	/*Free the memory taken from malloc*/
	if(payload_printable)
		free(payload_printable);
return;
}








