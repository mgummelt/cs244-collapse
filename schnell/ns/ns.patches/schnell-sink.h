#ifndef SCHNELL_SINK_H
#define SCHNELL_SINK_H

#include "agent.h"
#include "tcp.h"
#include "ip.h"
#include "timer-handler.h"

class SchnellSink;

class SchnellTimer : public TimerHandler {
	public:
		SchnellTimer(SchnellSink * ss): TimerHandler() { ss_ = ss; }
		virtual void expire(Event *e);
	protected:
		SchnellSink * ss_;
};

class SchnellSink : public Agent {
public:
	SchnellSink();
	void recv(Packet *pkt, Handler *);
	int command(int argc, const char*const* argv);
	void reset();
	virtual void sendNextAck();
	double & eRTT() { return eRTT_;} 
	double & initdelay() { return initdelay_;} 
protected:
	virtual void delay_bind_init_all();
	int lastAck;
	int lastSeg;
	int flowid;
	double eRTT_;
	double initdelay_;
	Packet * createAck(int seq);
	SchnellTimer acktimer;
};

class SchnellSinkAdapt: public SchnellSink {
	public:
		SchnellSinkAdapt();
		void sendNextAck();
	protected:
		int windowsize_;
		int maxwindowsize_;
		int slowstart_;
};

class SchnellSinkLazy: public SchnellSink {
	public:
		void recv(Packet *pkt, Handler *);

};


#endif
