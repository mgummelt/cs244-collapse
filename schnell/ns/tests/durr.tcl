#Create a simulator object
set ns [new Simulator]

#Open the nam trace file
set nf [open out.nam w]
$ns namtrace-all $nf

Agent/SchnellSink set packetSize_ 40
Agent/SchnellSink set eRTT_ 5ms


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
set client [$ns node]
set router [$ns node]

#Create a duplex link between the nodes
$ns duplex-link $victim $router 100Mb 1ms DropTail
$ns duplex-link $client $router 1Mb 10ms DropTail

$ns duplex-link-op $victim $router orient left
$ns duplex-link-op $client $router orient right-down


# create the agents
set send1 [ new Agent/TCP ]
set send2 [ new Agent/TCP ]
$ns attach-agent $victim $send1
$ns attach-agent $victim $send2
set recv1 [ new Agent/TCPSink ]
$ns attach-agent $client $recv1

# create the connections
$ns connect $send1 $recv1

$send1   set class_ 1                  # flow id

set ftp1 [new Application/FTP]
$ftp1 attach-agent $send1
$ns at 0.0 "$ftp1 start"

$ns color 1 Blue
#Monitor the queue for the link between node 2 and node 3
$ns duplex-link-op $client $router queuePos 0.5

#Call the finish procedure after 5 seconds of simulation time
$ns at 5.0 "finish"

#Run the simulation
$ns run
