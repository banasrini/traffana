#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <pthread.h>
#include "my402list.h"	
#include "my402list.c"
#include "cs402.h"		



/* default snap length (maximum bytes per packet to capture) per packet */
#define SNAP_LEN 1518
#define ZERO 0

/* ethernet headers are always exactly 14 bytes*/
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes 
#define ETHER_ADDR_LEN	6*/
	int tc=0;
	int sh =0;
	int tcp_count = 0;
	int verbose = -1;
	int udp_count = 0;
	int icmp_count = 0;
	int other_count = 0;
	int tot_count = 0;
	int byte_counter = 0;
	int timer_temp = 0;
	int timer_tempms = 0;
	int cur_time = 0;
	int duration = 0;
	int packet_length = 0;
	int write_flag = 0;
	
	FILE *fp = NULL;
	int devflag = 0;
	pthread_t TC;
	pthread_t SH;
	pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

	struct timeval ts;

// hw2 variables
	
	My402List *pt = NULL;
	int tcp_counttup2 = 0;
	int udp_counttup2 = 0;	
	
	int tcp_counttup5 = 0;
	int udp_counttup5 = 0;	
	int icmp_counttup5 = 0;

	int tup2_flag = 0;
	int tup5_flag = 0;
	int track_flag = 0;
	
	int count_tup2 = 0;
	int count_tup5 = 0;
	

	typedef struct tuple2 {
	    char srcIP[64];
	    char destIP[64];
	    int count;
	} Mytup2;

	typedef struct tuple5 {
		char srcIP[64];
               	char destIP[64];
		int src_port;
		int dest_port;
		int count;
		int prot;
	} Mytup5;


/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

struct UDP_hdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void * sig_han()
{
	if(write_flag == 1)
	fclose(fp);
	exit(0);
	pthread_exit(0);	
}

void handler(int sig)
{
	
	sh = pthread_create(&SH,NULL,sig_han,NULL);
    	if(sh){
		fprintf(stderr,"error creating thread");
		return;
	}
}

void print_usage() {
    printf("\n Usage: traffana -v [-r filename] [-i interface] [-T epoch] [ -w filename ] [-z {2|5} ]\n");
}

void print_stat() {
	if(verbose == 0)
	{
		if(track_flag == 0)
		{
			printf("%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,tcp_count,udp_count,icmp_count,other_count);
			cur_time = cur_time+duration;
		
		}
		else if(track_flag == 2)
		{
			printf("%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup2,tcp_count,udp_count,icmp_count,other_count,tcp_counttup2,udp_counttup2);
			cur_time = cur_time+duration;
			
			count_tup2 = 0;
			tup2_flag = 0;
			tcp_counttup2 = 0;
			udp_counttup2 = 0;
			My402ListUnlinkAll(pt);
		}
		else if(track_flag == 5)
		{
			printf("%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup5,tcp_count,udp_count,icmp_count,other_count,tcp_counttup5,udp_counttup5);
			cur_time = cur_time+duration;
			
			count_tup5 = 0;
			tcp_counttup5 = 0;
			udp_counttup5 = 0;
			tup5_flag =0;
			My402ListUnlinkAll(pt);
		}
		
	}
	else
	{ 
		if(track_flag == 0)
		{
			printf("%d.%6d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length);
			cur_time = cur_time+duration;
		}
		else if(track_flag == 2)
		{
			printf("%d.%6d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup2);
			cur_time = cur_time+duration;
			count_tup2 = 0;
			tup2_flag = 0;
			
			My402ListUnlinkAll(pt);
		}
		else if (track_flag == 5)
		{
			printf("%d.%6d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup5);
			cur_time = cur_time+duration;
			count_tup5 = 0;
			tup5_flag =0;
			My402ListUnlinkAll(pt);
		}
		
	}
	
}

void print_count() {
	if(verbose == 0)
	{
		if(track_flag == 0)
		{
			printf("%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,ZERO,ZERO,ZERO,ZERO,ZERO,ZERO);
			cur_time = cur_time+duration;
		}
		else if(track_flag == 2 || track_flag ==5)
		{
			printf("%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,ZERO,ZERO,ZERO,ZERO,ZERO,ZERO,ZERO,ZERO,ZERO);
			cur_time = cur_time+duration;
		}
		
	}
	else
	{
		if(track_flag == 0) // -z is not specified
		{ 
			printf("%d.%6d\t%d\t%d\n",cur_time,timer_tempms,ZERO,ZERO);
			cur_time = cur_time+duration;
		}
		else if(track_flag == 2 || track_flag ==5) // -z2 is specified
		{ 
			printf("%d.%06d\t%d\t%d\t%d\n",cur_time,timer_tempms,ZERO,ZERO,ZERO);
			cur_time = cur_time+duration;
		}
		
	}
}

void print_file_stat(){
	if(verbose == 0)
	{	
		if(track_flag == 0)
		{		
			fprintf(fp,"%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,tcp_count,udp_count,icmp_count,other_count);
			cur_time = cur_time+duration;
		}
		else if (track_flag == 2)
		{
			fprintf(fp,"%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup2,tcp_count,udp_count,icmp_count,other_count,tcp_counttup2,udp_counttup2);

			cur_time = cur_time+duration;
			count_tup2 = 0;
			tup2_flag = 0;
			tcp_counttup2 = 0;
			udp_counttup2 = 0;
			My402ListUnlinkAll(pt);
		}
		else if(track_flag == 5)
		{
			fprintf(fp,"%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup5,tcp_count,udp_count,icmp_count,other_count,tcp_counttup5,udp_counttup5);
			
			cur_time = cur_time+duration;
			count_tup5 = 0;
			tup5_flag = 0;
			tcp_counttup5 = 0;
			udp_counttup5 = 0;
			My402ListUnlinkAll(pt);
		}

	}
	else
	{ 
		if(track_flag == 0)
		{
			fprintf(fp,"%d.%6d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length);
			cur_time = cur_time+duration;
		}
		else if(track_flag == 2)
		{
			fprintf(fp,"%d.%6d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup2);
			cur_time = cur_time+duration;
			count_tup2 = 0;
			tup2_flag = 0;
			
			My402ListUnlinkAll(pt);	
		}
		else if(track_flag == 5)
		{
			fprintf(fp,"%d.%6d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup5);
			cur_time = cur_time+duration;
			count_tup5 = 0;
			tup5_flag =0;
			My402ListUnlinkAll(pt);
		}
	}


			
}

void print_file_count(){
	if(verbose == 0)
	{
		if(track_flag == 0)
		{
			fprintf(fp,"%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,ZERO,ZERO,ZERO,ZERO,ZERO,ZERO);
			cur_time = cur_time+duration;
		}
		else if (track_flag == 2 || track_flag == 5)
		{
			fprintf(fp,"%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,ZERO,ZERO,ZERO,ZERO,ZERO,ZERO,ZERO,ZERO,ZERO);
			cur_time = cur_time+duration;
		}
		

	}
	else
	{ 
		if(track_flag == 0)
		{
			fprintf(fp,"%d.%6d\t%d\t%d\n",cur_time,timer_tempms,ZERO,ZERO);
			cur_time = cur_time+duration;
		}
		if(track_flag == 2 || track_flag == 5)
		{
			fprintf(fp,"%d.%6d\t%d\t%d\t%d\n",cur_time,timer_tempms,ZERO,ZERO,ZERO);
			cur_time = cur_time+duration;
		}
		
	}
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
got_packet_live(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void * func() 
{
	while(1)
	{
		
		sleep(duration);		
		pthread_mutex_lock(&mut);
		if(write_flag == 1)
			print_file_stat();
		else
			print_stat();
		tot_count = 0;
		packet_length = 0;
		tcp_count = 0;
		udp_count = 0;
		icmp_count = 0;
		other_count = 0;		
		pthread_mutex_unlock(&mut);	
	}
	pthread_exit(0); 
}

void
got_packet_live(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp; 
	const struct UDP_hdr *udp;

	int size_ip;
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	udp = (struct UDP_hdr*) packet;
	/* determine protocol */	
	
	
	if(cur_time == 0)
	{   
		switch(ip->ip_p) {
				case IPPROTO_TCP:
					tcp_count++;
		
					break;
				case IPPROTO_UDP:
					udp_count++;
			
					break;
				case IPPROTO_ICMP:
					icmp_count++;
					break;
		
				default:
					other_count++;
					break;
			}		
		tc = pthread_create(&TC,NULL,func,NULL);
    		if(tc){
			fprintf(stderr,"error creating thread");
			return;
		} 
		tot_count = 1;
		packet_length+=header->len;
		cur_time = header->ts.tv_sec;
		timer_tempms = header->ts.tv_sec;

			if(track_flag ==2)
			{
				Mytup2 *tup2 = (Mytup2*)malloc(sizeof(Mytup2));
				strcpy(tup2->srcIP,inet_ntoa(ip->ip_src));
				strcpy(tup2->destIP,inet_ntoa(ip->ip_dst));
				tup2->count = 1;
				count_tup2 = 1;
				tup2_flag = 1;	// flag = 1 indicates that the packet is not the first one in this epoch.

				if(ip->ip_p == IPPROTO_TCP)
				{
					tcp_counttup2++;
				}
				else if(ip->ip_p == IPPROTO_UDP)
				{
					udp_counttup2++;
				}

				My402ListAppend(pt, (void*)tup2);
				return;
			}
			else if(track_flag == 5)
			{
				Mytup5 *tup5 = (Mytup5*)malloc(sizeof(Mytup5));

				strcpy(tup5->srcIP,inet_ntoa(ip->ip_src));
				strcpy(tup5->destIP,inet_ntoa(ip->ip_dst));
				if(ip->ip_p == IPPROTO_TCP)
				{
					tcp_counttup5++;
				
					tup5->src_port = ntohs(tcp->th_sport);
					tup5->dest_port = ntohs(tcp->th_dport);
					tup5->prot = 1;
				}
				else if(ip->ip_p == IPPROTO_UDP)
				{
					udp_counttup5++;
				
					tup5->src_port = ntohs(udp->uh_sport);
					tup5->dest_port = ntohs(udp->uh_dport);
					tup5->prot = 2;
				}
				else if(ip->ip_p == IPPROTO_ICMP)
				{
					icmp_counttup5++;
				
					tup5->src_port = 0;
					tup5->dest_port = 0;
					tup5->prot = 3;
				}
				
				tup5->count = 1;
				count_tup5 = 1;
				tup5_flag = 1;	// flag = 1 indicates that the packet is not the first one in this epoch.
				
				My402ListAppend(pt, (void*)tup5);
				return;
			}
	 
		 
	}

	else if( cur_time!=0)
	{
		switch(ip->ip_p) {
		case IPPROTO_TCP:
			tcp_count++;
		
			break;
		case IPPROTO_UDP:
			udp_count++;
			
			break;
		case IPPROTO_ICMP:
			icmp_count++;
			break;
		
		default:
			other_count++;
			break;
	}
		tot_count++;
		packet_length+=header->len;

		if(track_flag == 2)
		{
			if(tup2_flag == 0)
			{
				Mytup2 *tup2 = (Mytup2*)malloc(sizeof(Mytup2));
				strcpy(tup2->srcIP,inet_ntoa(ip->ip_src));
				strcpy(tup2->destIP,inet_ntoa(ip->ip_dst));
				tup2->count = 1;
				count_tup2 = 1;
				tup2_flag = 1;	// flag = 1 indicates that the packet is not the first one in this epoch.

				// counting the number of tcp and udp flows for -z2 -v
				if(ip->ip_p == IPPROTO_TCP)
				{
					tcp_counttup2++;
				}
				else if(ip->ip_p == IPPROTO_UDP)
				{
					udp_counttup2++;
				}	

				My402ListAppend(pt, (void*)tup2);
				return;
			}
			else if(tup2_flag == 1)
			{
				char temp_src[64] = {'\0'};
				char temp_dst[64] = {'\0'};
				strcpy(temp_src,inet_ntoa(ip->ip_src));
				strcpy(temp_dst,inet_ntoa(ip->ip_dst));
		
				My402ListElem *traverse=NULL;
		   		traverse=&(pt->anchor);
		    		traverse=traverse->next;
				int flag_found = 0;
				while(traverse!=&(pt->anchor))
				{
					Mytup2 *tuptemp2=(Mytup2*)(traverse->obj);
			
					if((strcmp(temp_src,tuptemp2->srcIP)==0) && strcmp(temp_dst, tuptemp2->destIP)==0)
					{
						flag_found = 1;
						break;
				
					}
					traverse=traverse->next;
				}
		
				if(flag_found == 0)
				{
					Mytup2 *tup2 = (Mytup2*)malloc(sizeof(Mytup2));
					strcpy(tup2->srcIP,inet_ntoa(ip->ip_src));
					strcpy(tup2->destIP,inet_ntoa(ip->ip_dst));
					tup2->count=1;
					count_tup2++; // total count of diff flows

					// counting the number of tcp flows and udp flows for -z2 -v
					if(ip->ip_p == IPPROTO_TCP)
					{
						tcp_counttup2++;
					}
					else if(ip->ip_p == IPPROTO_UDP)
					{
						udp_counttup2++;
					}

					My402ListAppend(pt, (void*)tup2);
				
				}
			}
		
		}
		if(track_flag == 5)
		{
			if(tup5_flag == 0)
			{
				Mytup5 *tup5 = (Mytup5*)malloc(sizeof(Mytup5));

				strcpy(tup5->srcIP,inet_ntoa(ip->ip_src));
				strcpy(tup5->destIP,inet_ntoa(ip->ip_dst));
				if(ip->ip_p == IPPROTO_TCP)
				{
					tcp_counttup5++;
					tup5->src_port = ntohs(tcp->th_sport);
					tup5->dest_port = ntohs(tcp->th_dport);
					tup5->prot = 1;
				}
				else if(ip->ip_p == IPPROTO_UDP)
				{
					udp_counttup5++;
					tup5->src_port = ntohs(udp->uh_sport);
					tup5->dest_port = ntohs(udp->uh_dport);
					tup5->prot = 2;
				}	
				else if(ip->ip_p == IPPROTO_ICMP)
				{
					icmp_counttup5++;
					tup5->src_port = 0;
					tup5->dest_port = 0;
					tup5->prot = 3;
				}
				
				tup5->count = 1;
				count_tup5 = 1;
				tup5_flag = 1;	// flag = 1 indicates that the packet is not the first one in this epoch.
	
				My402ListAppend(pt, (void*)tup5);
				return;
			}
			else if(tup5_flag == 1)
			{
				char temp_src[64] = {'\0'};
				char temp_dst[64] = {'\0'};
				int temp_sport = 0;
				int temp_dport = 0;
				int temp_prot = 0;

				strcpy(temp_src,inet_ntoa(ip->ip_src));
				strcpy(temp_dst,inet_ntoa(ip->ip_dst));

				if(ip->ip_p == IPPROTO_TCP)
				{
					temp_sport = ntohs(tcp->th_sport);
					temp_dport = ntohs(tcp->th_dport);
					temp_prot = 1;
				}
				else if(ip->ip_p == IPPROTO_UDP)
				{
					temp_sport = ntohs(udp->uh_sport);
					temp_dport = ntohs(udp->uh_dport);
					temp_prot = 2;
				}
				else if(ip->ip_p == IPPROTO_ICMP)
					{
						
						temp_prot = 3;
					}

				My402ListElem *traverse=NULL;
		   		traverse=&(pt->anchor);
		    		traverse=traverse->next;
				int flag_found = 0;
				while(traverse!=&(pt->anchor))
				{
					Mytup5 *tuptemp5=(Mytup5*)(traverse->obj);
					
					if((strcmp(temp_src,tuptemp5->srcIP)==0) && (strcmp(temp_dst, tuptemp5->destIP)==0) && (tuptemp5->prot == temp_prot))
					{

						if(ip->ip_p == IPPROTO_TCP)
						{

							if((tuptemp5->src_port == temp_sport) && (tuptemp5->dest_port ==  temp_dport))
							{ 
								flag_found = 1;
								break;
							}
						}
						else if(ip->ip_p == IPPROTO_UDP)
						{
							if((tuptemp5->src_port == temp_sport) && (tuptemp5->dest_port ==  temp_dport))
							{ 
								flag_found = 1;
								break;
							}
						}
						else if(ip->ip_p == IPPROTO_ICMP)
						{
								flag_found = 1;
								break;
						}
						
						
				
					}
					traverse=traverse->next;
				}
				
				if(flag_found == 0)
				{
					
					Mytup5 *tup5 = (Mytup5*)malloc(sizeof(Mytup5));

					strcpy(tup5->srcIP,inet_ntoa(ip->ip_src));
					strcpy(tup5->destIP,inet_ntoa(ip->ip_dst));

					if(ip->ip_p == IPPROTO_TCP)
					{
						tcp_counttup5++;
						tup5->src_port = ntohs(tcp->th_sport);
						tup5->dest_port = ntohs(tcp->th_dport);
						tup5->prot = 1;
					}
					else if(ip->ip_p == IPPROTO_UDP)
					{
						udp_counttup5++;
						tup5->src_port = ntohs(udp->uh_sport);
						tup5->dest_port = ntohs(udp->uh_dport);
						tup5->prot = 2;
					}
					if(ip->ip_p == IPPROTO_ICMP)
					{
						icmp_counttup5++;
						tup5->src_port = 0;
						tup5->dest_port = 0;
						tup5->prot = 3;
					}

					tup5->count=1;
					count_tup5++; // total count of diff flows
				
					

					My402ListAppend(pt, (void*)tup5);
				
				}
			}
		}
	}
	
}


void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{


	/* declare pointers to packet headers */
	
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp; 
	const struct UDP_hdr *udp;
	
	int size_ip;
		

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	udp = (struct UDP_hdr*) packet;

	

	
	
	if(write_flag == 0 && devflag == 0)
	{
		if(cur_time == 0)
		{
		 	switch(ip->ip_p) {
				case IPPROTO_TCP:
					tcp_count++;
		
					break;
				case IPPROTO_UDP:
					udp_count++;
			
					break;
				case IPPROTO_ICMP:
					icmp_count++;
					break;
		
				default:
					other_count++;
					break;
			}
			cur_time = (int)header->ts.tv_sec;
			timer_tempms = (int)header->ts.tv_usec;
			tot_count = 1;
			
			packet_length+=header->len;


			
	// creating an element belonging to the list and setting its object as the tuple 2 structure

			if(track_flag ==2)
			{
				Mytup2 *tup2 = (Mytup2*)malloc(sizeof(Mytup2));
				strcpy(tup2->srcIP,inet_ntoa(ip->ip_src));
				strcpy(tup2->destIP,inet_ntoa(ip->ip_dst));
				tup2->count = 1;
				count_tup2 = 1;
				tup2_flag = 1;	// flag = 1 indicates that the packet is not the first one in this epoch.

				if(ip->ip_p == IPPROTO_TCP)
				{
					tcp_counttup2++;
				}
				else if(ip->ip_p == IPPROTO_UDP)
				{
					udp_counttup2++;
				}

				My402ListAppend(pt, (void*)tup2);
				return;
			}
			else if(track_flag == 5)
			{
				Mytup5 *tup5 = (Mytup5*)malloc(sizeof(Mytup5));

				strcpy(tup5->srcIP,inet_ntoa(ip->ip_src));
				strcpy(tup5->destIP,inet_ntoa(ip->ip_dst));
				if(ip->ip_p == IPPROTO_TCP)
				{
					tcp_counttup5++;
				
					tup5->src_port = ntohs(tcp->th_sport);
					tup5->dest_port = ntohs(tcp->th_dport);
					tup5->prot = 1;
				}
				else if(ip->ip_p == IPPROTO_UDP)
				{
					udp_counttup5++;
				
					tup5->src_port = ntohs(udp->uh_sport);
					tup5->dest_port = ntohs(udp->uh_dport);
					tup5->prot = 2;
				}
				else if(ip->ip_p == IPPROTO_ICMP)
				{
					icmp_counttup5++;
				
					tup5->src_port = 0;
					tup5->dest_port = 0;
					tup5->prot = 3;
				}
				
				tup5->count = 1;
				count_tup5 = 1;
				tup5_flag = 1;	// flag = 1 indicates that the packet is not the first one in this epoch.
				
				My402ListAppend(pt, (void*)tup5);
				return;
			}
			return;
		}
	
	// check if the packet belongs to the next epoch
	if(((int)header->ts.tv_sec + ((int)header->ts.tv_usec * 0.000001)) > (cur_time + (timer_tempms*0.000001) + duration))
	{
		print_stat();
		while((((int)header->ts.tv_sec) >= (cur_time + duration)) && ((int)header->ts.tv_sec >= timer_tempms))
		{
			
			print_count();
		}
			
			tot_count = 1;
			packet_length = header->len;
			tcp_count = 0;
			udp_count = 0;
			icmp_count = 0;
			other_count = 0;
			switch(ip->ip_p) {
				case IPPROTO_TCP:
					tcp_count++;
		
					break;
				case IPPROTO_UDP:
					udp_count++;
			
					break;
				case IPPROTO_ICMP:
					icmp_count++;
					break;
		
				default:
					other_count++;
					break;
			}
	}
	else // belongs to same epoch, so keep counting the packets.
	{
		// check if the source and destination of this packet belongs to the same flow as the previous packet.
		/* determine protocol */	
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				tcp_count++;
		
				break;
			case IPPROTO_UDP:
				udp_count++;
			
				break;
			case IPPROTO_ICMP:
				icmp_count++;
				break;
		
			default:
				other_count++;
				break;
		}
		tot_count++;
		packet_length+=header->len;

		if(track_flag == 2)
		{
			if(tup2_flag == 0)
			{
				Mytup2 *tup2 = (Mytup2*)malloc(sizeof(Mytup2));
				strcpy(tup2->srcIP,inet_ntoa(ip->ip_src));
				strcpy(tup2->destIP,inet_ntoa(ip->ip_dst));
				tup2->count = 1;
				count_tup2 = 1;
				tup2_flag = 1;	// flag = 1 indicates that the packet is not the first one in this epoch.

				// counting the number of tcp and udp flows for -z2 -v
				if(ip->ip_p == IPPROTO_TCP)
				{
					tcp_counttup2++;
				}
				else if(ip->ip_p == IPPROTO_UDP)
				{
					udp_counttup2++;
				}	

				My402ListAppend(pt, (void*)tup2);
				return;
			}
			else if(tup2_flag == 1)
			{
				char temp_src[64] = {'\0'};
				char temp_dst[64] = {'\0'};
				strcpy(temp_src,inet_ntoa(ip->ip_src));
				strcpy(temp_dst,inet_ntoa(ip->ip_dst));
		
				My402ListElem *traverse=NULL;
		   		traverse=&(pt->anchor);
		    		traverse=traverse->next;
				int flag_found = 0;
				while(traverse!=&(pt->anchor))
				{
					Mytup2 *tuptemp2=(Mytup2*)(traverse->obj);
			
					if((strcmp(temp_src,tuptemp2->srcIP)==0) && strcmp(temp_dst, tuptemp2->destIP)==0)
					{
						flag_found = 1;
						break;
				
					}
					traverse=traverse->next;
				}
		
				if(flag_found == 0)
				{
					Mytup2 *tup2 = (Mytup2*)malloc(sizeof(Mytup2));
					strcpy(tup2->srcIP,inet_ntoa(ip->ip_src));
					strcpy(tup2->destIP,inet_ntoa(ip->ip_dst));
					tup2->count=1;
					count_tup2++; // total count of diff flows

					// counting the number of tcp flows and udp flows for -z2 -v
					if(ip->ip_p == IPPROTO_TCP)
					{
						tcp_counttup2++;
					}
					else if(ip->ip_p == IPPROTO_UDP)
					{
						udp_counttup2++;
					}

					My402ListAppend(pt, (void*)tup2);
				
				}
			}
		
		}
		if(track_flag == 5)
		{
			if(tup5_flag == 0)
			{
				Mytup5 *tup5 = (Mytup5*)malloc(sizeof(Mytup5));

				strcpy(tup5->srcIP,inet_ntoa(ip->ip_src));
				strcpy(tup5->destIP,inet_ntoa(ip->ip_dst));
				if(ip->ip_p == IPPROTO_TCP)
				{
					tcp_counttup5++;
					tup5->src_port = ntohs(tcp->th_sport);
					tup5->dest_port = ntohs(tcp->th_dport);
					tup5->prot = 1;
				}
				else if(ip->ip_p == IPPROTO_UDP)
				{
					udp_counttup5++;
					tup5->src_port = ntohs(udp->uh_sport);
					tup5->dest_port = ntohs(udp->uh_dport);
					tup5->prot = 2;
				}	
				else if(ip->ip_p == IPPROTO_ICMP)
				{
					icmp_counttup5++;
					tup5->src_port = 0;
					tup5->dest_port = 0;
					tup5->prot = 3;
				}
				
				tup5->count = 1;
				count_tup5 = 1;
				tup5_flag = 1;	// flag = 1 indicates that the packet is not the first one in this epoch.
	
				My402ListAppend(pt, (void*)tup5);
				return;
			}
			else if(tup5_flag == 1)
			{
				char temp_src[64] = {'\0'};
				char temp_dst[64] = {'\0'};
				int temp_sport = 0;
				int temp_dport = 0;
				int temp_prot = 0;

				strcpy(temp_src,inet_ntoa(ip->ip_src));
				strcpy(temp_dst,inet_ntoa(ip->ip_dst));

				if(ip->ip_p == IPPROTO_TCP)
				{
					temp_sport = ntohs(tcp->th_sport);
					temp_dport = ntohs(tcp->th_dport);
					temp_prot = 1;
				}
				else if(ip->ip_p == IPPROTO_UDP)
				{
					temp_sport = ntohs(udp->uh_sport);
					temp_dport = ntohs(udp->uh_dport);
					temp_prot = 2;
				}
				else if(ip->ip_p == IPPROTO_ICMP)
					{
						
						temp_prot = 3;
					}

				My402ListElem *traverse=NULL;
		   		traverse=&(pt->anchor);
		    		traverse=traverse->next;
				int flag_found = 0;
				while(traverse!=&(pt->anchor))
				{
					Mytup5 *tuptemp5=(Mytup5*)(traverse->obj);
					
					if((strcmp(temp_src,tuptemp5->srcIP)==0) && (strcmp(temp_dst, tuptemp5->destIP)==0) && (tuptemp5->prot == temp_prot))
					{

						if(ip->ip_p == IPPROTO_TCP)
						{

							if((tuptemp5->src_port == temp_sport) && (tuptemp5->dest_port ==  temp_dport))
							{ 
								flag_found = 1;
								break;
							}
						}
						else if(ip->ip_p == IPPROTO_UDP)
						{
							if((tuptemp5->src_port == temp_sport) && (tuptemp5->dest_port ==  temp_dport))
							{ 
								flag_found = 1;
								break;
							}
						}
						else if(ip->ip_p == IPPROTO_ICMP)
						{
								flag_found = 1;
								break;
						}
						
						
				
					}
					traverse=traverse->next;
				}
				
				if(flag_found == 0)
				{
					
					Mytup5 *tup5 = (Mytup5*)malloc(sizeof(Mytup5));

					strcpy(tup5->srcIP,inet_ntoa(ip->ip_src));
					strcpy(tup5->destIP,inet_ntoa(ip->ip_dst));

					if(ip->ip_p == IPPROTO_TCP)
					{
						tcp_counttup5++;
						tup5->src_port = ntohs(tcp->th_sport);
						tup5->dest_port = ntohs(tcp->th_dport);
						tup5->prot = 1;
					}
					else if(ip->ip_p == IPPROTO_UDP)
					{
						udp_counttup5++;
						tup5->src_port = ntohs(udp->uh_sport);
						tup5->dest_port = ntohs(udp->uh_dport);
						tup5->prot = 2;
					}
					if(ip->ip_p == IPPROTO_ICMP)
					{
						icmp_counttup5++;
						tup5->src_port = 0;
						tup5->dest_port = 0;
						tup5->prot = 3;
					}

					tup5->count=1;
					count_tup5++; // total count of diff flows
				
					

					My402ListAppend(pt, (void*)tup5);
				
				}
			}
		}
	}
}

	else if(write_flag == 1 && devflag == 0)
	{
		if(cur_time == 0)
		{
			switch(ip->ip_p) {
				case IPPROTO_TCP:
					tcp_count++;
		
					break;
				case IPPROTO_UDP:
					udp_count++;
			
					break;
				case IPPROTO_ICMP:
					icmp_count++;
					break;
		
				default:
					other_count++;
					break;
			}
			cur_time = (int)header->ts.tv_sec;
			timer_tempms = (int)header->ts.tv_usec;
			tot_count = 1;
		
			packet_length+=header->len;

			// creating an element belonging to the list and setting its object as the tuple structure
			if(track_flag ==2)
			{
				Mytup2 *tup2 = (Mytup2*)malloc(sizeof(Mytup2));
				strcpy(tup2->srcIP,inet_ntoa(ip->ip_src));
				strcpy(tup2->destIP,inet_ntoa(ip->ip_dst));
				tup2->count = 1;
				count_tup2 = 1;
				tup2_flag = 1;	// flag = 1 indicates that the packet is not the first one in this epoch.

				if(ip->ip_p == IPPROTO_TCP)
				{
					tcp_counttup2++;
				}
				else if(ip->ip_p == IPPROTO_UDP)
				{
					udp_counttup2++;
				}

				My402ListAppend(pt, (void*)tup2);
				return;
			}

			else if(track_flag == 5)
			{
				Mytup5 *tup5 = (Mytup5*)malloc(sizeof(Mytup5));

				strcpy(tup5->srcIP,inet_ntoa(ip->ip_src));
				strcpy(tup5->destIP,inet_ntoa(ip->ip_dst));
				if(ip->ip_p == IPPROTO_TCP)
				{
					tcp_counttup5++;
				
					tup5->src_port = ntohs(tcp->th_sport);
					tup5->dest_port = ntohs(tcp->th_dport);
					tup5->prot = 1;
				}
				else if(ip->ip_p == IPPROTO_UDP)
				{
					udp_counttup5++;
				
					tup5->src_port = ntohs(udp->uh_sport);
					tup5->dest_port = ntohs(udp->uh_dport);
					tup5->prot = 2;
				}
				else if(ip->ip_p == IPPROTO_ICMP)
				{
					icmp_counttup5++;
					
					tup5->prot = 3;
				}
				tup5->count = 1;
				count_tup5 = 1;
				tup5_flag = 1;	// flag = 1 indicates that the packet is not the first one in this epoch.
				
				My402ListAppend(pt, (void*)tup5);
				return;
			}
			return;
		}
		if(((int)header->ts.tv_sec + ((int)header->ts.tv_usec * 0.000001)) > (cur_time + (timer_tempms*0.000001) + duration))
		{
			print_file_stat();
		
			while((((int)header->ts.tv_sec) >= (cur_time + duration)) && ((int)header->ts.tv_sec >= timer_tempms))
			{
				print_file_count();
			}

			tot_count = 1;
			packet_length = header->len;
			tcp_count = 0;
			udp_count = 0;
			icmp_count = 0;
			other_count = 0;
			switch(ip->ip_p) {
				case IPPROTO_TCP:
					tcp_count++;
		
					break;
				case IPPROTO_UDP:
					udp_count++;
			
					break;
				case IPPROTO_ICMP:
					icmp_count++;
					break;
		
				default:
					other_count++;
					break;
			}
		}
		else // if the packets belong to the same epoch
		{
			// check if the source and destination of this packet belongs to the same flow as the previous packet.
					/* determine protocol */	
			switch(ip->ip_p) {
				case IPPROTO_TCP:
					tcp_count++;
		
					break;
				case IPPROTO_UDP:
					udp_count++;
			
					break;
				case IPPROTO_ICMP:
					icmp_count++;
					break;
		
				default:
					other_count++;
					break;
			}
			tot_count++;
			packet_length+=header->len;
			if(track_flag == 2)
			{
				if(tup2_flag == 0)
				{
					Mytup2 *tup2 = (Mytup2*)malloc(sizeof(Mytup2));
					strcpy(tup2->srcIP,inet_ntoa(ip->ip_src));
					strcpy(tup2->destIP,inet_ntoa(ip->ip_dst));
					tup2->count = 1;
					count_tup2 = 1;
					tup2_flag = 1;	// flag = 1 indicates that the packet is not the first one in this epoch.

					// counting the number of tcp and udp flows for -z2 -v
					if(ip->ip_p == IPPROTO_TCP)
					{
						tcp_counttup2++;
					}
					else if(ip->ip_p == IPPROTO_UDP)
					{
						udp_counttup2++;
					}	

					My402ListAppend(pt, (void*)tup2);
					return;
				}
				else if(tup2_flag == 1)
				{
					char temp_src[64] = {'\0'};
					char temp_dst[64] = {'\0'};
					strcpy(temp_src,inet_ntoa(ip->ip_src));
					strcpy(temp_dst,inet_ntoa(ip->ip_dst));
		
					My402ListElem *traverse=NULL;
			   		traverse=&(pt->anchor);
			    		traverse=traverse->next;
					int flag_found = 0;
					while(traverse!=&(pt->anchor))
					{
						Mytup2 *tuptemp2=(Mytup2*)(traverse->obj);
			
						if((strcmp(temp_src,tuptemp2->srcIP)==0) && strcmp(temp_dst, tuptemp2->destIP)==0)
						{
							flag_found = 1;
							break;
				
						}
						traverse=traverse->next;
					}
		
					if(flag_found == 0)
					{
						Mytup2 *tup2 = (Mytup2*)malloc(sizeof(Mytup2));
						strcpy(tup2->srcIP,inet_ntoa(ip->ip_src));
						strcpy(tup2->destIP,inet_ntoa(ip->ip_dst));
						tup2->count=1;
						count_tup2++; // total count of diff flows

						// counting the number of tcp flows and udp flows for -z2 -v
						if(ip->ip_p == IPPROTO_TCP)
						{
							tcp_counttup2++;
						}
						else if(ip->ip_p == IPPROTO_UDP)
						{
							udp_counttup2++;
						}

						My402ListAppend(pt, (void*)tup2);
				
					}
				}
		
			}
			if(track_flag == 5)
			{
				if(tup5_flag == 0)
				{
					Mytup5 *tup5 = (Mytup5*)malloc(sizeof(Mytup5));

					strcpy(tup5->srcIP,inet_ntoa(ip->ip_src));
					strcpy(tup5->destIP,inet_ntoa(ip->ip_dst));
					if(ip->ip_p == IPPROTO_TCP)
					{
						tcp_counttup5++;
						tup5->src_port = ntohs(tcp->th_sport);
						tup5->dest_port = ntohs(tcp->th_dport);
						tup5->prot = 1;
					}
					else if(ip->ip_p == IPPROTO_UDP)
					{
						udp_counttup5++;
						tup5->src_port = ntohs(udp->uh_sport);
						tup5->dest_port = ntohs(udp->uh_dport);
						tup5->prot = 2;
					}	
					else if(ip->ip_p == IPPROTO_ICMP)
					{
						icmp_counttup5++;
						tup5->src_port = 0;
						tup5->dest_port = 0;
						tup5->prot = 3;
					}	

					tup5->count = 1;
					count_tup5 = 1;
					tup5_flag = 1;	// flag = 1 indicates that the packet is not the first one in this epoch.
	
					My402ListAppend(pt, (void*)tup5);
					return;
				}
				else if(tup5_flag == 1)
				{
					char temp_src[64] = {'\0'};
					char temp_dst[64] = {'\0'};
					int temp_sport = 0;
					int temp_dport = 0;
					int temp_prot = 0;

					strcpy(temp_src,inet_ntoa(ip->ip_src));
					strcpy(temp_dst,inet_ntoa(ip->ip_dst));

					if(ip->ip_p == IPPROTO_TCP)
					{
						temp_sport = ntohs(tcp->th_sport);
						temp_dport = ntohs(tcp->th_dport);
						temp_prot = 1;
					}
					else if(ip->ip_p == IPPROTO_UDP)
					{
						temp_sport = ntohs(udp->uh_sport);
						temp_dport = ntohs(udp->uh_dport);
						temp_prot = 2;
					}
					else if(ip->ip_p == IPPROTO_ICMP)
					{
						
						temp_prot = 3;
					}

					My402ListElem *traverse=NULL;
			   		traverse=&(pt->anchor);
			    		traverse=traverse->next;
					int flag_found = 0;
					while(traverse!=&(pt->anchor))
					{
						Mytup5 *tuptemp5=(Mytup5*)(traverse->obj);
					
						if((strcmp(temp_src,tuptemp5->srcIP)==0) && (strcmp(temp_dst, tuptemp5->destIP)==0) && (tuptemp5->prot == temp_prot))
						{

							if(ip->ip_p == IPPROTO_TCP)
							{

								if((tuptemp5->src_port == temp_sport) && (tuptemp5->dest_port ==  temp_dport))
								{ 
									flag_found = 1;
									break;
								}
							}
							else if(ip->ip_p == IPPROTO_UDP)
							{
								if((tuptemp5->src_port == temp_sport) && (tuptemp5->dest_port ==  temp_dport))
								{ 
									flag_found = 1;
									break;
								}
							}

							else if(ip->ip_p == IPPROTO_ICMP)
							{
								
									flag_found = 1;
									break;
								
							}
				
						}
						traverse=traverse->next;
					}
				
					if(flag_found == 0)
					{
					
						Mytup5 *tup5 = (Mytup5*)malloc(sizeof(Mytup5));

						strcpy(tup5->srcIP,inet_ntoa(ip->ip_src));
						strcpy(tup5->destIP,inet_ntoa(ip->ip_dst));

						if(ip->ip_p == IPPROTO_TCP)
						{
							tcp_counttup5++;
							tup5->src_port = ntohs(tcp->th_sport);
							tup5->dest_port = ntohs(tcp->th_dport);
							tup5->prot = 1;
						}
						else if(ip->ip_p == IPPROTO_UDP)
						{
							udp_counttup5++;
							tup5->src_port = ntohs(udp->uh_sport);
							tup5->dest_port = ntohs(udp->uh_dport);
							tup5->prot = 2;
						}
						else if(ip->ip_p == IPPROTO_ICMP)
						{
							icmp_counttup5++;
							tup5->src_port = 0;
							tup5->dest_port = 0;
							tup5->prot = 3;
						}

						tup5->count=1;
						count_tup5++; // total count of diff flows
				
					

						My402ListAppend(pt, (void*)tup5);
				
					}
				}
			
			}
	
		}
	}
	

return;
}

int main(int argc, char *argv[]) {	
    int opt= 0;
    int fileflag = 0;
    char *filename = NULL;
    char *outfilename = NULL;
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;				/* packet capture handle */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */
    struct bpf_program fpe;
    char filter_exp[] = "ip";
    
    static struct option long_options[] = {
        {"verbose",      no_argument,       0,  'v' },
        {"read", required_argument,       0,  'r' },
        {"int",    required_argument, 0,  'i' },
        {"time",   required_argument, 0,  'T' },
	{"write",   required_argument, 0,  'w' },
	{"track",   required_argument, 0,  'z' },
        {0,           0,                 0,  0   }
    };

    int long_index =0;
    while ((opt = getopt_long(argc, argv,"vr:i:T:w:z:", 
                   long_options, &long_index )) != -1) {
        switch (opt) {
             case 'v' : verbose = 0;
                 break;
             case 'r' : filename = optarg;
		 fileflag = 1;
                 break;
             case 'i' : dev = optarg;
		 devflag = 1;

                 break;
             case 'T' : duration = atof(optarg);
                 break;
	     case 'w' : outfilename = optarg;
		 fp = fopen(outfilename,"w");
		 write_flag = 1;
                 break;
	     case 'z' : track_flag = atoi(optarg);
		 break;
	     case ' ' : print_usage();
                 break;
             default: print_usage(); 
                 exit(EXIT_FAILURE);
        }
    }

	if (argc < 2)
	{ 
		print_usage(); 
		exit(1); 
	} 

        if (duration == 0.0)
	{
		duration = 1.0;
	}

	
   

        if((dev == NULL) && (filename == NULL))
	{
		print_usage();
		exit(1);
	}

	if((devflag == 1) && (fileflag == 1))
	{
		print_usage();
		exit(1);
	}

        if(fileflag == 1)
	{ 
    		handle = pcap_open_offline(filename, errbuf);   
	    	if (handle == NULL) 
		{ 
	      		fprintf(stderr,"Couldn't open pcap file %s: %s\n",filename, errbuf); 
	      		return(2); 
	    	} 
        }
	
	
	//hw2 variables
	pt=(My402List*)malloc(sizeof(My402List));
    	My402ListInit(pt);

        if(devflag == 1)
	{	
		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(EXIT_FAILURE);
		}
	}

		/* get network number and mask associated with capture device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
		{
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
			    dev, errbuf);
			net = 0;
			mask = 0;
		
		}

	void handler(int);
	signal(SIGINT,handler);
	
	// compiling the filter
        if(pcap_compile(handle, &fpe, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Error calling pcap_compile\n");
		exit(1);
        }
 
   	// setting the filter
        if(pcap_setfilter(handle, &fpe) == -1) {
		fprintf(stderr, "Error setting filter\n");
		exit(1);
    } 

	// offline mode
	if(fileflag == 1)
	{
		pcap_loop(handle, -1, got_packet, NULL);
	}
	
	// online mode
	if(devflag == 1)
	{ 
		pcap_loop(handle, -1, got_packet_live, NULL);
	}

	pcap_close(handle);

	if(write_flag == 0)
	{
		if(verbose == 0)
		{
			if(track_flag ==0)
			{
				printf("%d.%06d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,tcp_count,udp_count,icmp_count,other_count);
				cur_time = cur_time+duration;
			}
			else if(track_flag == 2)
			{				
				printf("%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup2,tcp_count,udp_count,icmp_count,other_count,tcp_counttup2,udp_counttup2);
				cur_time = cur_time+duration;
				count_tup2 = 0;
				tup2_flag = 0;
				tcp_counttup2 = 0;
				udp_counttup2 = 0;
				My402ListUnlinkAll(pt);
			}
			else if(track_flag == 5)
			{
				printf("%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup5,tcp_count,udp_count,icmp_count,other_count,tcp_counttup5,udp_counttup5);

				cur_time = cur_time+duration;
				count_tup5 = 0;
				tup5_flag = 0;
				tcp_counttup5 = 0;
				udp_counttup5 = 0;
				My402ListUnlinkAll(pt);
			}
			
		}
		else
		{ 
			if(track_flag == 0)
			{
				printf("%d.%06d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length);
				cur_time = cur_time+duration;
			}
			else if(track_flag == 2)
			{
				printf("%d.%06d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup2);
				cur_time = cur_time+duration;
				count_tup2 = 0;
				tup2_flag = 0;
				My402ListUnlinkAll(pt);
			}
			else if(track_flag == 5)
			{
				printf("%d.%06d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup5);
				cur_time = cur_time+duration;
				count_tup5 = 0;
				tup5_flag = 0;
				My402ListUnlinkAll(pt);
			}
			

		}
	}
	else
	{
		if(verbose == 0)
			{	
				if(track_flag == 0)
				{		
					fprintf(fp,"%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,tcp_count,udp_count,icmp_count,other_count);
					cur_time = cur_time+duration;
				}
				else if (track_flag == 2)
				{
					fprintf(fp,"%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup2,tcp_count,udp_count,icmp_count,other_count,tcp_counttup2,udp_counttup2);

					cur_time = cur_time+duration;
					count_tup2 = 0;
					tup2_flag = 0;
					tcp_counttup2 = 0;
					udp_counttup2 = 0;
					My402ListUnlinkAll(pt);
				}
				else if(track_flag == 5)
				{
					fprintf(fp,"%d.%6d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup5,tcp_count,udp_count,icmp_count,other_count,tcp_counttup5,udp_counttup5);
			
					cur_time = cur_time+duration;
					count_tup5 = 0;
					tup5_flag = 0;
					tcp_counttup5 = 0;
					udp_counttup5 = 0;
					My402ListUnlinkAll(pt);
				}

			}
				
			
		else
		{ 
			if(track_flag == 0)
			{
				fprintf(fp,"%d.%6d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length);
				cur_time = cur_time+duration;
			}
			else if(track_flag == 2)
			{
				fprintf(fp,"%d.%6d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup2);
				cur_time = cur_time+duration;
				count_tup2 = 0;
				tup2_flag = 0;
			
				My402ListUnlinkAll(pt);	
			}
			else if(track_flag == 5)
			{
				fprintf(fp,"%d.%6d\t%d\t%d\t%d\n",cur_time,timer_tempms,tot_count,packet_length,count_tup5);
				cur_time = cur_time+duration;
				count_tup5 = 0;
				tup5_flag =0;
				My402ListUnlinkAll(pt);
			}
			
		}
			
	}
	
	// closing the file if opened
	if(write_flag == 1)
		fclose(fp);
	
	pthread_join(TC,NULL);

    return 0;
}	
