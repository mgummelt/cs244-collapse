#ifndef PACKETQUEUE_H
#define PACKETQUEUE_H

/* thread safe packet queue, that stores sequence numbers and arrival times
 */

struct packetqueue;

#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/select.h>

#include "schnell.h"


typedef struct packet {
	unsigned int seq;
	struct timeval  arrival;
	struct packet * next;
} packet;

typedef struct packetqueue {
	pthread_mutex_t * lock;
	pthread_cond_t * cond;
	int count;
	packet * data;
} packetqueue;

packetqueue * packetqueue_create();
packet * pq_dequeue(packetqueue *, struct timespec * timeout);
packet * pq_dequeue_nowait(packetqueue *);
int pq_enqueue(packetqueue*,unsigned int seq, struct timeval arrival);
int pq_isempty(packetqueue *);
int pq_waitforpacket(packetqueue *,struct timespec *timeout);

	

#endif 
