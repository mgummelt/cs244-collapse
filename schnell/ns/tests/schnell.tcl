#Create a simulator object
set ns [new Simulator]
set tcpagent Agent/TCP
set maxwindow 655

#Open the nam trace file
set nf [open out.nam w]
$ns namtrace-all $nf

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
$ns duplex-link $victim $lrouter 10Mb 10ms DropTail
$ns duplex-link $client $rrouter 100Mb 10ms DropTail
$ns duplex-link $attacker $rrouter 1Mb 10ms DropTail
$ns duplex-link $lrouter $rrouter 10Mb 10ms DropTail

$ns duplex-link-op $victim $lrouter orient left
$ns duplex-link-op $attacker $rrouter orient right-up
$ns duplex-link-op $client $rrouter orient right-down
$ns duplex-link-op $rrouter $lrouter orient center


#Monitor the queue for the link between node 2 and node 3
$ns duplex-link-op $victim $lrouter queuePos 0.5
$ns duplex-link-op $client $rrouter queuePos 0.5

# Setup the client
set tcp1 [$ns create-connection TCP $victim TCPSink $client 42]
$tcp1  set window_ $maxwindow         # configure the TCP agent;
$tcp1  set class_ 1                   # flow id

# Old attacker, for testing
# set tcp2 [$ns create-connection TCP $victim TCPSink $attacker 42]
# $tcp2  set window_ $maxwindow                   # configure the TCP agent;

# Setup the attacker
set send [new $tcpagent ]
set schnell [new Agent/SchnellSinkLazy ]
$ns attach-agent $victim $send
$ns attach-agent $attacker $schnell
$ns connect $send $schnell
$schnell set packetSize_ 40
$schnell set eRTT_ 5ms
$schnell set maxwindowsize_ $maxwindow
$send  set class_ 2                   # flow id

set ftp1 [new Application/FTP]
$ftp1 attach-agent $tcp1
set ftp2 [new Application/FTP]
$ftp2 attach-agent $send

$ns at 0.5 "$ftp1 start"
$ns at 0.0 "$ftp2 start"

$ns color 1 Blue
$ns color 2 Red

#Call the finish procedure after 5 seconds of simulation time
$ns at 5.0 "finish"

#Run the simulation
$ns run
