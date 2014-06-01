#usage 
#$0 number_of_nodes [-full]

#parameters
#set filesize 1e6
set rtt 20ms

#class declarations
Class Application/FTPSource -superclass Application

Class Application/FTPSink -superclass Application

Application/FTPSink instproc stopAt {nbytes what} {
    $self instvar bytesLeft
    $self instvar stopAction
    set bytesLeft $nbytes		
    set stopAction $what
}

Application/FTPSink instproc recv { nbytes} {
    $self instvar bytesLeft
    $self instvar stopAction
    set bytesLeft [expr $bytesLeft - $nbytes]
    if { $bytesLeft <= 0 } {
	eval $stopAction
	set stopAction ""
    }
}

Class CountdownAction 

CountdownAction instproc init {start_counter action_} {
    $self instvar count
    $self instvar action
    set count $start_counter
    set action $action_
}

CountdownAction instproc down {} {
    $self instvar count
    $self instvar action

    set count [expr $count - 1] 
    if { $count == 0 } {
	eval $action
    }
}
    


#Create a simulator object
set ns [new Simulator]


if { $argc < 3 || $argv > 4 } {
    puts stderr "usage: ns alpha.tcl nnodes filesize bandwidth \[-full\]"
    exit 2
}
set nnodes [lindex $argv 0]
set filesize [expr [lindex $argv 1] + 0 ] 
set bandwidth [lindex $argv 2]
set option [lindex $argv 3]

puts "Using $nnodes different nodes"


set full 0
if { $option eq "-full" } {
    set full 1
    puts "Full Tcp"
} else { 
    if { $option ne "" } {
	puts stderr "Invalid option -- $option"
    } else { 
	puts "TCP and TCPSink"
    }
}

#set end 60

#Open the nam trace file
if { $full } {
    set pref full
} else { 
    set pref out
}

set outfile $pref-$nnodes.nam
set nf [open $outfile w]
$ns namtrace-all $nf

#Define a 'finish' procedure
proc finish {} {
        global ns nf outfile
        $ns flush-trace
        #Close the trace file
        close $nf
        #Execute nam on the trace file
        #exec nam $outfile &
        exit 0
}

#Create two nodes
set router [$ns node]
set server [$ns node]
$ns duplex-link $server $router $bandwidth $rtt DropTail

set cdown [new CountdownAction $nnodes "finish"]

#Create a duplex link between the nodes
for {set i 0} {$i < $nnodes} {incr i} {
    set node($i) [$ns node]
    $ns duplex-link  $node($i) $router $bandwidth $rtt DropTail


    if { $full } {
	set src [new Agent/TCP/FullTcp]
	set sink [new Agent/TCP/FullTcp]
    } else {
	set src [new Agent/TCP]
	set sink [new Agent/TCPSink]
    }
    $ns attach-agent $server $src
    $ns attach-agent $node($i) $sink

    set ftpsource($i) [new Application/FTPSource]
    $ftpsource($i) attach-agent $src
    
    set ftpsink($i) [new Application/FTPSink] 
    $ftpsink($i) attach-agent $sink  
    $ftpsink($i) stopAt $filesize \
	"$ftpsource($i) stop; $ftpsink($i) stop; $cdown down"
    $ns at 0 "$ftpsink($i) start"
    $ns at 0.1 "$ftpsource($i) start; $ftpsource($i) send $filesize"


    $ns connect $src $sink
    $sink listen

    lappend nodelist $node($i)
}

#$ns at $end "exit 0"

#Run the simulation
$ns run

