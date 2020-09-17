#!/usr/bin/perl -w

use Socket;
use File::Basename; use Getopt::Long;
use XML::LibXML;

GetOptions('debug'=>\$debug,
	   'force'=>\$force,
	   'email=s'=>\$emailto,);

my $dirname = dirname(__FILE__);
chdir $dirname;

my $cmd;

$cmd = "nmap -sn 192.168.1.0/24 -oX -";
$cmd .= " 2>/dev/null" unless $debug;

my $xml = `$cmd`;
print STDERR "$xml\n" if $debug;

my %hosts;

my $dom = XML::LibXML->load_xml(string=>$xml);
my @nmaphosts = $dom->findnodes("/nmaprun/host");
foreach my $node (@nmaphosts) {
    my $state = '';
    my $addr = '';
    my $status = $node->find("./status");
    if ($status->[0]) {
	my $attributes = $status->[0]->attributes();
	$state = $attributes->getNamedItem("state")->getValue() || '';
    }
    my $address = $node->find("./address");
    if ($address->[0]) {
	my $attributes = $address->[0]->attributes();
	$addr = $attributes->getNamedItem("addr")->getValue() || '';
    }
    print "$addr $state\n" if $debug;
    $hosts{$addr} = {};
    $hosts{$addr}->{state} = $state;
}

# load self
my $interface = '';
my $hwaddr = '';
my $inetaddr = '';
foreach my $line (split /\n/, `/sbin/ifconfig 2>/dev/null`) {
    chomp $line;
    if ($line =~ m!^(\S+) !o) {
	$interface = $1;
	if ($interface eq 'lo') {
	    $interface = '';
	    $hwaddr = '';
	    $inetaddr = '';
	    next;
	}
    }
    next unless $interface;
    if ($line =~ m!HWaddr (..:..:..:..:..:..)!o) {
	$hwaddr = $1;
    }
    if ($line =~ m!inet addr:(\d+\.\d+\.\d+\.\d+)!o) {
	$inetaddr = $1;
	$hosts{$inetaddr} = {};
	$hosts{$inetaddr}->{state} = "active";
	$hosts{$inetaddr}->{mac} = $hwaddr;
    }
}


foreach my $line (split /\n/, `/usr/sbin/arp -an 2>/dev/null`) {
    if ($line =~ m!\((\d+\.\d+\.\d+\.\d+)\) at (\S+:\S+:\S+:\S+:\S+:\S+)!o) {
	my ($ip,$mac)= ($1, $2);
	$mac = fix_mac($mac);
	if (!exists $hosts{$ip}) {
	    $hosts{$ip} = {};
	    $hosts{$ip}->{state} = "unpingable";
	}
	$hosts{$ip}->{mac} = $mac;
	print "$ip, $mac\n" if $debug;
    }
}

my $upnp_checked = 0;
my %upnp_location = ();

my %prevmacs;
if (open(PREV,"prevmacs.txt")) {
    while (<PREV>) {
	my $line = $_;
	chomp $line;
	my @fields = split /\t/, $line;
	my $mac = $fields[0];
	next unless $mac;
	$prevmacs{$mac}{ip} = $fields[1];
	$prevmacs{$mac}{ts} = $fields[3];
	$prevmacs{$mac}{prevmanuf} = $fields[4];
    }
    close PREV;
}

$macprefixes = read_oui();

my $now = time();
my $message = '';
my $changes = 0;

foreach my $ip (sort compare_ips keys %hosts) {
   my $mac = $hosts{$ip}->{mac};
   next unless $mac;
   if (!exists $prevmacs{$mac}) {
       $changes = 1;
   }
}

if ($changes || $force) {
    foreach my $ip (sort compare_ips keys %hosts) {
	my $mac = $hosts{$ip}->{mac};
	next unless $mac;
	my $prefix = $mac;
	$prefix =~ s!^(..:..:..):.+!$1!o;
	$prefix =~ s!:!-!go;
	my $manuf = $macprefixes->{$prefix} || 'unknown';
	$hosts{$ip}->{manuf} = $manuf;
	my $hostname = get_hostname($ip) || '';
	if (!exists $prevmacs{$mac}) {
	    $message .= "New MAC address: $mac ($manuf) $ip ($hostname)\n";
	}
	$prevmacs{$mac}{ip} = $ip;
	$prevmacs{$mac}{hostname} = $hostname;
	$prevmacs{$mac}{ts} = $now;
	$prevmacs{$mac}{active} = 'active';
	$prevmacs{$mac}{manuf} = $manuf;
    }
}

if ($changes || $force) {
    if (open(NEW,">prevmacs.txt")) {
	foreach my $mac (sort compare_macs keys %prevmacs) {
	    print NEW join("\t",$mac,
			   $prevmacs{$mac}{ip}||'',
			   $prevmacs{$mac}{hostname}||'',
			   $prevmacs{$mac}{ts}||'',
			   $prevmacs{$mac}{manuf}||$prevmacs{$mac}{prevmanuf}||'',
			   $prevmacs{$mac}{active}||'');
	    print NEW "\n";
	}
	close NEW;
    }
}


if ($message) {
    if ($debug) {
	print "$message\n";
    }
    else {
	mail($emailto,"arpcheck update",$message);
    }
}

exit;

sub read_oui {
    my %macprefixes = ();
    # curl -O http://standards-oui.ieee.org/oui.txt
    if (open(OUI,"oui.txt")) {
	while (<OUI>) {
	    my $line = $_;
	    chomp $line;
	    $line =~ s!\r!!go;
	    my @fields = split /\t/, $line;
	    if ($fields[0] && $fields[2]) {
		if ($fields[0] =~ m!^(\S+-\S+-\S+) +\(hex\)!o) {
		    my $prefix = lc $1;
		    $macprefixes{$prefix} = $fields[2];
		}
	    }
	}
	close OUI;
    }
    return \%macprefixes;
}

sub compare_ips {
    my $aa = exists $prevmacs{$a} ? ($prevmacs{$a}{ip} || $a) : $a;
    my $bb = exists $prevmacs{$b} ? ($prevmacs{$b}{ip} || $b) : $b;
    my @aparts = split /\./, $aa;
    my @bparts = split /\./, $bb;
    return ($aparts[0] <=> $bparts[0]) ||
	($aparts[1] <=> $bparts[1]) ||
	($aparts[2] <=> $bparts[2]) ||
	($aparts[3] <=> $bparts[3]);
}

sub compare_macs {
    return (($prevmacs{$b}{active}||'') cmp ($prevmacs{$a}{active}||'')) ||
	(compare_ips($prevmacs{$a}{ip},$prevmacs{$b}{ip})) ||
	$a cmp $b;
}

sub fix_mac {
    my ($mac) = @_;
    my @parts;
    foreach my $part (split /:/, $mac) {
	$part = '0'.$part if length($part)==1;
	push @parts, $part;
    }
    return join(":", @parts);
}

sub get_hostname {
    my ($ip) = @_;
    
    my $hostname;
    $hostname = `dig +short -x $ip \@224.0.0.251 -p 5353 +timeout=1 +tries=1`;
    chomp $hostname;
    $hostname = '' if $hostname =~ m!;;!o;
    return $hostname if $hostname;
    
    $hostname = gethostbyaddr(inet_aton($ip),AF_INET);
    return $hostname if $hostname;
    
    if (!$hostname) {
	upnp_discover();
	my $url = $upnp_location{$ip};
	if ($url) {
	    my $xml = `curl -m 2 $url 2>/dev/null`;
	    $xml =~ s!(<\w+)\s+xmlns="(?:.+?)"!$1!og;
	    if ($xml) {
		print "\n\n$xml\n\n" if $debug;
		eval {
		    my $dom = XML::LibXML->load_xml(string=>$xml);
		    $hostname = $dom->findvalue("/root/device/friendlyName") || '';
		    $hostname =~ s!\s+!_!go;
		};
	    }
	}
    }
    return $hostname;
}

sub upnp_discover {
    return if $upnp_checked;
    %upnp_location = ();
    if (-x "/usr/bin/gssdp-discover") {
	my $ulist = `/usr/bin/gssdp-discover --timeout 2 --target upnp:rootdevice 2>/dev/null`;
	foreach my $line (split /\n/, $ulist) {
	    if ($line =~ /Location: (\S+)/o) {
		my $url = $1;
		if ($url =~ m!//(.+):\d+/!o) {
		    $upnp_location{$1} = $url;
		}
	    }
	}
    }
    $upnp_checked = 1;
}
    

sub mail {
    my ($to,$subject,$message) = @_;
    return unless $to && $subject;
    $message = "Subject: $subject\n\n$message\n";
    
    if ($debug) {
	print "$message\n";
    }
    else {
	my $mail = qq[msmtp $to];
	open MAIL,"| $mail";
	print MAIL $message;
	close MAIL;
    }
}
