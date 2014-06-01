/***************************************************
 * Schnell Sink class
 * 	modeling evil doers since 1996
 */


#include "schnell-sink.h"

/**************************************************************************
 * TCL stuff
 */


static class SchnellSinkClass: public TclClass {
	public:
		SchnellSinkClass() : TclClass("Agent/SchnellSink") {
		}
		TclObject * create(int argc , const char*const* argv){
			return (new SchnellSink());
		}
} class_schnellsink;

static class SchnellSinkAdaptClass: public TclClass {
	public:
		SchnellSinkAdaptClass() : TclClass("Agent/SchnellSinkAdapt") {
		}
		TclObject * create(int argc , const char*const* argv){
			return (new SchnellSinkAdapt());
		}
} class_schnellsinkadapt;


static class SchnellSinkLazyClass: public TclClass {
	public:
		SchnellSinkLazyClass() : TclClass("Agent/SchnellSinkLazy") {
		}
		TclObject * create(int argc , const char*const* argv){
			return (new SchnellSinkLazy());
		}
} class_schnellsinklazy;
/*************************************************************************
 * Schnell Adapt class
 */
SchnellSinkAdapt::SchnellSinkAdapt(){
	windowsize_=1; 
	maxwindowsize_=1000;
	slowstart_ = 1;
	bind("maxwindowsize_",&maxwindowsize_);
}

void SchnellSinkAdapt::sendNextAck(){
	Packet *npkt;
	lastAck+=windowsize_;
	npkt = createAck(lastAck);
	send(npkt,0);
	if(slowstart_){
		windowsize_+=2;
		if(windowsize_>maxwindowsize_){
			slowstart_=0;
			windowsize_=maxwindowsize_;
			//fprintf(stderr,"SchnellSinkAdapt::SchnellSinkAdapt:: "
			//		"going from slowstart to CC\n");
		}
	}
}

/**************************************************************************
 * Schnell Lazy Class
 */

void SchnellSinkLazy::recv(Packet *pkt, Handler *){
	hdr_tcp *otcp = hdr_tcp::access(pkt);           // incoming data tcp header
	int seqno= otcp->seqno();
	if(lastSeg == -1){		// first packet of flow
		hdr_ip* oip = hdr_ip::access(pkt);
		flowid= oip->flowid();
		lastSeg=seqno;
		lastAck=seqno;
		Packet::free(pkt);
	}
	lastSeg=seqno;
	sendNextAck();			// send ACK right away
}


/**************************************************************************
 * Schnell Base class 
 */
void SchnellSink::recv(Packet *pkt, Handler *){
	hdr_tcp *otcp = hdr_tcp::access(pkt);           // incoming data tcp header
	int seqno= otcp->seqno();

	if(lastSeg == -1){		// first packet of flow
		hdr_ip* oip = hdr_ip::access(pkt);
		flowid= oip->flowid();
		lastSeg=seqno;
		lastAck=seqno;
		acktimer.sched(initdelay());
		Packet::free(pkt);
		return;
	}
	if(seqno == lastSeg )		// retranmision
		lastAck=seqno;
	lastSeg=seqno;
}


void SchnellSink::sendNextAck(){
	lastAck++;
	Packet* npkt = createAck(lastAck);
	send(npkt, 0);
}

Packet * SchnellSink::createAck(int seq){
	Packet* npkt = allocpkt();
        double now = Scheduler::instance().clock();
        hdr_tcp *ntcp = hdr_tcp::access(npkt);
	hdr_ip* nip = hdr_ip::access(npkt);
	nip->flowid() = flowid;			// sets the ip headers and everything

	ntcp->seqno() = seq;
	ntcp->ts()=now;					//set the creation time
	return npkt;
}

void SchnellSink::delay_bind_init_all() {
	delay_bind_init_one("packetSize_");
	delay_bind_init_one("eRTT_");
	delay_bind_init_one("initdelay_");
	Agent::delay_bind_init_all();
}

	
SchnellSink::SchnellSink(): Agent(PT_ACK),acktimer(this){
	bind("packetSize_", &size_);
	bind_time("eRTT_", &eRTT_);
	bind_time("initdelay_", &initdelay_);
	lastSeg=lastAck=-1;
}

void SchnellSink::reset(){
	return;
}

int SchnellSink::command(int argc, char const* const* argv){
	/*
	fprintf(stderr, "Called SchnellSink::command :\n");
	for(int i=0;i<argc;i++)
		fprintf(stderr,"	arg %d is '%s'\n",i,argv[i]);
		*/
	return (Agent::command(argc, argv));
}



/**************************************************************************
 * Timer Stuff
 */

void SchnellTimer::expire(Event *e){
	ss_->sendNextAck();
	this->resched( ss_->eRTT());
}

