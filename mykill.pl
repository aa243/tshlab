#!/usr/bin/perl

# Variant of kill command that can use names, not just process IDs
# Usage: kill <name>


if (@ARGV == 0) {
    print "Usage: $ARGV[0] name\n";
    exit(0);
}
    
$tname = $ARGV[0];

$jobs = `/bin/ps`;

$found = 0;

for $j (split /\n/, $jobs) {
    # Trim off leading spaces
    $j =~ s/^\s+//;
    @fields = split /\s+/, $j;
    $pid = $fields[0];
    $name = $fields[-1];
    if ($name eq $tname) {
	system "kill $pid" || die "Couldn't kill $pid\n";
	print "Killed $tname\n";
	$found = 1;
    }
}

die "Couldn't find job named $tname\n" unless $found == 1;


