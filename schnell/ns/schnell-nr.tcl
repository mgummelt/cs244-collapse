#Create a simulator object
set ns [new Simulator]
set wscale 14
set packet_size 1460
set victimTCP Agent/TCP
#set victimTCP Agent/TCP/Newreno
set attackTCP Agent/SchnellSinkAdapt
#set attackTCP Agent/TCPSink
set randomseed 0
set colors [list "Red" "Blue" "Green" "Yellow" "Black" "Purple" "White" ]
set server_bandwidth 	100Mb
set server_delay	10ms
set nvictims -1
set stoptime 5.0
#set packetqueuelen 50 - NS default
# linux default
set packetqueuelen 1000		

##################################
#  Args parsing 

if { $argc != 5 } { 
	    puts stderr "usage: ns schnell.tcl <nvictims> <psize> <wscale> <bw> <time(s)>";
	        exit 2
}
set nvictims [lindex $argv 0]
set packet_size [lindex $argv 1]
set wscale [lindex $argv 2]
set attacker_bandwidth [lindex $argv 3]
set attacker_bandwidth_ns "${attacker_bandwidth}b"
set stoptime [lindex $argv 4]

##############################################3
# initilization

set cwnd [ expr [expr pow(2,16)] * [expr pow( 2,$wscale)]]
set maxwindow [ expr ceil ( double($cwnd) / double($packet_size) ) ]
set outfile [join [split "out-$nvictims-$packet_size-$wscale-${attacker_bandwidth_ns}-$stoptime.nam" "/"] "."]
# calc delay between sends
set attacker_delay [ expr { ( 1000.0 * 8 * 40.0 * $nvictims ) / double($attacker_bandwidth) }]
set eRTT "${attacker_delay}ms"
set startdelta [expr $attacker_delay / $nvictims ]
Queue set limit_ $packetqueuelen
puts "Attack options: v=$nvictims ;ACKd: $eRTT : bw $attacker_bandwidth_ns"
puts "		mw $maxwindow ps $packet_size : cw $cwnd: ql $packetqueuelen"


expr { srand($randomseed)}

#############################################
# Actual Simulator
#Open the nam trace file
set logfile [open $outfile w]
$ns namtrace-all $logfile

#Define a 'finish' procedure
proc finish {} {
        global ns logfile outfile
        $ns flush-trace
	#Close the trace file
        close $logfile
	#Execute nam on the trace file
        #exec nam $outfile &
        exit 0
}


#Create nodes
set attacker [$ns node]
set trouter [$ns node]

#Create a duplex link between the nodes
$ns duplex-link $attacker $trouter $attacker_bandwidth_ns 10ms DropTail

$ns duplex-link-op $attacker $trouter orient down


#Monitor the queue for the link between node 2 and node 3
$ns duplex-link-op $attacker $trouter queuePos 0.5

#Setup the victims
for {set i 0} {$i < $nvictims } {incr i} {
	set victim($i) [$ns node]
	$ns duplex-link  $victim($i) $trouter $server_bandwidth $server_delay DropTail
	#$ns duplex-link-op $trouter $victim($i) orient top


	set src [new $victimTCP]
	set sink [new $attackTCP]

	$src set packetSize_ $packet_size
	$sink set packetSize_ $packet_size
	$src set window_ $maxwindow
	$sink set window_ $maxwindow

	$ns attach-agent $victim($i) $src
	$ns attach-agent $attacker $sink
	set c [expr $i % [llength $colors] + 1 ]
	$src set class_ $c

	$sink set packetSize_ 40	# ACK packets, not data packets
	$sink set eRTT_ $eRTT
	$sink set maxwindowsize_ $maxwindow
	$sink set initdelay_ "${attacker_delay}ms"

	set ftpsource($i) [new Application/FTP]
	$ftpsource($i) attach-agent $src

	# join in order
	set t [expr { ( $i * $startdelta ) / 1000 }]
	$ns at $t  "$ftpsource($i) start"

	$ns connect $src $sink
	lappend nodelist $victim($i)
	set tmp [lindex $colors [ expr { $c - 1 } ]]
	#puts "Node $i assigned to class $c ($tmp) at time $t "
#	$ns create-trace Hop $logfile $victim($i) $trouter nam
}

for {set i 0 } {$i < [llength $colors]} {incr i} {
	# Sets the nodes colors
	#puts "Set class [expr $i + 1] to [lindex $colors $i]"
	$ns color [expr $i + 1] [ lindex $colors $i]
}


#Call the finish procedure after 5 seconds of simulation time
$ns at $stoptime "finish"

#Run the simulation
$ns run
