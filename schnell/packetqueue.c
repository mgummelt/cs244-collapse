#include "packetqueue.h"

/* create
 */
packetqueue * packetqueue_create(){
	packetqueue *q = malloc(sizeof(packetqueue));
	assert(q);
	q->lock = malloc(sizeof(pthread_mutex_t));
	q->cond = malloc(sizeof(pthread_cond_t));
	assert(q->lock);
	assert(q->cond);
	pthread_mutex_init(q->lock,NULL);
	pthread_cond_init(q->cond,NULL);
	q->count=0;
	q->data=NULL;
	return q;
}

/* enqueue
 */
int pq_enqueue(packetqueue* q,unsigned int seq, struct timeval arrival){
	packet * neop;
	packet * curr;
	// make new packet
	neop = malloc(sizeof(packet));
	neop->seq=seq;
	neop->arrival=arrival;
	neop->next=NULL;
	// lock stuff
	pthread_mutex_lock(q->lock);
	// insert stuff
	if(q->data ==NULL){
		q->data=neop;
	} else{
		curr=q->data;
		while(curr->next!=NULL)
			curr=curr->next;
		curr->next=neop;
	}
	q->count++;
	// wake up anyone waiting
	pthread_cond_signal(q->cond);
	pthread_mutex_unlock(q->lock);
	return 0;
}


/* dequeue
 */
packet * pq_dequeue(packetqueue * q, struct timespec * timeout){
	packet * w;
	int err;
	pthread_mutex_lock(q->lock);
	while(q->count<1){	// repeat until something in queue
		err=pthread_cond_timedwait(q->cond,q->lock,timeout);
		if(err==ETIMEDOUT){
			pthread_mutex_unlock(q->lock);
			return NULL;
		}
		// if there is nothing in the queue, just loop and try again
	}
	w = q->data;
	q->data=q->data->next;
	assert(w);
	q->count--;
	pthread_mutex_unlock(q->lock);
	return w;
}
/* dequeue no wait
 */
packet * pq_dequeue_nowait(packetqueue*q){
	packet * w;
	pthread_mutex_lock(q->lock);
	if(q->count<1){
		pthread_mutex_unlock(q->lock);
		return NULL;
	}
	w = q->data;
	q->data=q->data->next;
	assert(w);
	q->count--;
	pthread_mutex_unlock(q->lock);
	return w;
}


/* int pq_isempty(packetqueue *);
 */
int pq_isempty(packetqueue *q){
	int empty;
	pthread_mutex_lock(q->lock);
	empty=(q->count==0);
	pthread_mutex_unlock(q->lock);
	return empty;
}


/* wait for packet; don't get it
 */
int pq_waitforpacket(packetqueue *q,struct timespec *timeout){
	int err,gotpacket;
	pthread_mutex_lock(q->lock);
	if(q->count>0){
		pthread_mutex_unlock(q->lock);
		return 1;	// got packet before waiting
	}
	err=pthread_cond_timedwait(q->cond,q->lock,timeout);
	if((err==0)&&(q->count>0))
		gotpacket=1;
	else
		gotpacket=0;
	pthread_mutex_unlock(q->lock);
	return gotpacket;
}


