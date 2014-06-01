set ns [new Simulator]

set nf [open out.nam w]
$ns namtrace-all $nf


proc finish {} {
	global ns nf
	$ns flush-trace
	close $nf
	exec nam out.nam &
	exit 0
}

$ns at 5.0 "finish"

set n0 [$ns node]
set n1 [$ns node]

ns duplex-link $n0 $n1 1Mb 10ms DropTail


# attach agent
set udp0 [new Agent/UDP]
$ns attach-agent $n0 $udp0
#Create a constant bit rate traffic source

set cbr0 [new Application/Traffic/CBR]
$cbr0 set packetSize_ 500
$cbr0 set internal_ 0.005
$cbr0 set attach-agent $udp0

set null0 [new Agent/Null]
$ns attach-agent $n1 $null0

$ns connect $udp0 $null0

$ns at 0.5 "$cbr0 start"
$ns at 4.5 "$cbr0 stop"

$ns run
