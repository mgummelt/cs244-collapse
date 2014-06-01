# Global options
set maxwindow 655
set myQueueSize 100



#Create a simulator object
set ns [new Simulator]

#Open the nam trace file
set nf [open out.nam w]
$ns namtrace-all $nf


#Agent/SchnellSink set packetSize_ 40
#Agent/SchnellSink set eRTT_ 20ms


#Define a 'finish' procedure
proc finish {} {
        global ns nf
        $ns flush-trace
	#Close the trace file
        close $nf
	#Execute nam on the trace file
        exec nam out.nam &
        exit 0
}

#Create nodes
set victim [$ns node]
set attacker [$ns node]
set client [$ns node]
set lrouter [$ns node]
set rrouter [$ns node]

#Create a duplex link between the nodes
$ns duplex-link $victim $rrouter 100Mb 1ms DropTail
$ns queue-limit $victim $rrouter $myQueueSize
$ns duplex-link $client $lrouter 100Mb 1ms DropTail
$ns queue-limit $client $lrouter $myQueueSize
$ns duplex-link $rrouter $lrouter 10Mb 10ms DropTail
$ns queue-limit $rrouter $lrouter $myQueueSize
$ns duplex-link $attacker $lrouter 1Mb 10ms DropTail
$ns queue-limit $attacker $lrouter $myQueueSize

$ns duplex-link-op $victim $rrouter orient right
$ns duplex-link-op $attacker $lrouter orient left-up
$ns duplex-link-op $rrouter $lrouter orient center
$ns duplex-link-op $client $lrouter orient left-down

#Monitor the queue for the link between node 2 and node 3
$ns duplex-link-op $lrouter $rrouter queuePos 0.5
$ns duplex-link-op $attacker $lrouter queuePos 0.5
$ns duplex-link-op $victim $rrouter queuePos 0.5

# create the agents
set send1 [ new Agent/TCP ]
set send2 [ new Agent/TCP ]
$ns attach-agent $victim $send1
$ns attach-agent $victim $send2
set recv1 [ new Agent/TCPSink ]
$ns attach-agent $client $recv1
set schnell [ new Agent/SchnellSinkAdapt ]
#set schnell [ new Agent/SchnellSink ]
#set schnell [ new Agent/TCPSink ]
$ns attach-agent $attacker $schnell

# create the connections
$ns connect $send1 $recv1
$ns connect $send2 $schnell
# configure tcp
$send1 set window_ $maxwindow		# unbounded
$send1 set window_ $maxwindow
# configure schnell
$schnell set packetSize_ 40
$schnell set eRTT_ 10ms
$schnell set maxwindowsize_ $maxwindow


$send1   set class_ 1                  # flow id
$send2  set class_ 2                   # flow id


set ftp1 [new Application/FTP]
$ftp1 attach-agent $send1
set ftp2 [new Application/FTP]
$ftp2 attach-agent $send2

$ns at 0.0 "$ftp1 start"
$ns at 0.5 "$ftp2 start"

$ns color 1 Blue
$ns color 2 Red

#Call the finish procedure after 5 seconds of simulation time
$ns at 5.0 "finish"

#Run the simulation
$ns run
