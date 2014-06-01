#!/usr/bin/perl -w 

$sinkid=0;
$srcid=3;

$sinkseq=$srcseq=$sinktime=$srctime=0;


while(<>){
                     # + -t 0.32367   -s 3       -d 2    -p tcp -e 1500 -c 0   -i 46  -a 0   -x {3.0 0.0 29 
	next unless(/^\+ -t ([\d\.]+) -s (\d+) -d (\d+)/);
	$t=$1;
	$s=$2;
	$d=$3;	$d=$d;
#r -t 0.0302435333333333 -s 1 -d 0 -p tcp -e 40 -c 0 -i 0 -a 0 -x {3.0 0.0 0 ------- null}
	next unless(/(\d+) -------/);
	$seq=$1;
	if($d==$srcid){	# from server's prospective
		$sinktime=$t;
		$sinkseq=$seq;
	} elsif($s==$srcid){
		$srctime=$t;
		$srcseq=$seq;
	} else {
		next;
	}
	print "$srctime	$srcseq	$sinktime $sinkseq\n";
}
print STDERR "p \"f\" u 1:2 ti \"Src\" w lp, \"f\" u 3:4 ti \"Sink\" w lp\n"
