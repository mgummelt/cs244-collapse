#!/usr/bin/perl -w

$delta=shift || 0.010;

#h -t 0 -s 8 -d 2 -p tcp -e 40 -c 6 -i 5 -a 6 -x {8.0 0.5 -1 ------- null}

foreach $file (@ARGV){
	$lasttime=0;
	foreach $key ( keys %counts){
		delete $counts{$key};
	}
	open IN, $file or die "open IN :$!";
	open OUT, ">bparsed-$file" or die "open OUT: $!";
	while(<IN>){
		next unless(/^h -t ([\.\d+]+) -s (\d+) -d (\d+) -p tcp -e (\d+)/);
		$t=$1;
		$s=$2;
		$d=$3;
		$size=$4;
		next if(($s<=2)||($d!=2));	# skip anything except server traffic
		if(($t-$lasttime)>$delta){
			print OUT "$lasttime	";
			foreach $key (sort keys %counts){
				print OUT " : $key $counts{$key}";
				$counts{$key}=0;
			}	
			print OUT "\n";
			$lasttime=$t;
		}
		$counts{$s}+=$size;
	}
	print OUT "$lasttime	";
	foreach $key (sort keys %counts){
		print OUT " : $key $counts{$key}";
		$counts{$key}=0;
	}	
	print OUT "\n";
}
