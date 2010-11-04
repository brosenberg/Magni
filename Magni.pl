#!/usr/bin/perl -w
# MAGNI v0.1
# Very simple shell based network probing and monitoring tool.
# Ben Rosenberg
# 24 Oct 2010

# Note: This version is an initial concept and is not intended to be particularly clean or easily modifiable. The purpose was to get a general idea of how Magni would actually work and what would be required of it. In the next version this script will be broken up into separate Perl modules for each general function.

# Todo:
#   Break this into separate Perl modules
#   Automatically choose a device to sniff on during startup
#   Write pcap dumps to a file
#   Read pcap dumps from files
#   Arguments for commands
#   Network replay
#   ARP poisoning
#   Use of Readline
#    Navigate history
#    Arrow keys
#   And so much more!

# General Code Layout:
#  Main Code
#  Shell Subroutines
#  General Subroutines

################################## Main Code ###################################

use strict;
use Net::Pcap;
use NetPacket::ARP;
use NetPacket::Ethernet;
use NetPacket::ICMP;
use NetPacket::IGMP;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use Socket;

my $program_name = eval { (caller)[1]; };
(my $program_base_name = $program_name) =~ s/^.*\///;
(my $program_dir = $program_name) =~ s/^(.*)\/.+?$/$1/;

$|=1;

my @history; # Shell history
my $manual_file = "$program_dir/README";

# User definable options
my $environ = {
    "MOTD" => "What do you require of MAGNI?",
    "PROMPT" => "MAGNI> ",
    "HIST_SIZE" => 500,
    "PROMISCUOUS" => 1,
    "SNAPLEN" => 1024,
    "TIMEOUT" => 20,
    "PRINT_DATA" => 0,
    "PRINT_PACKETS" => 0,
    "SERVICE_DETECT" => 0,
};

# Non-user definable options
my $internals = {
    "capture_iface_name" => "",
    "capture_iface" => "",
    "ifaces" => {},
    "interrupt" => 0,
};

# This hash can be populated with service signatures.
# The key is the name of the service, the value is an array of regular expressions that will match for that service.
my $service_sigs = {
    #"ssh" => [ qr/SSH-/mi ],
};

$SIG{HUP} = \&sig_exit;
$SIG{INT} = \&ctrl_c;
$SIG{QUIT} = \&sig_exit;
$SIG{TERM} = \&sig_exit;

# Builtin commands. The key is the name of the command, the hash it points to contains "sub" which is the subroutine that will be run when the builtin is run, and "desc" a brief description of the command.
my $builtins = {
    "?" => {
                "sub"  => \&sh_help,
                "desc" => "Print this help",
              },
    "clear" => {
                "sub"  => sub { system("clear"); },
                "desc" => "Clear the screen",
              },
    "env" => {
                "sub"  => \&sh_print_environ,
                "desc" => "Print environ contents",
              },
    "exit" => {
                "sub"  => \&seppuku,
                "desc" => "Exit the shell",
              },
    "help" => {
                "sub"  => \&sh_help,
                "desc" => "Print this help",
              },
    "history" => {
                "sub"  => \&sh_history,
                "desc" => "Print command history",
              },
    "iflist" => {
                "sub"  => \&int_iflist,
                "desc" => "List available ifaces",
              },
    "listen" => {
                "sub"  => \&int_set_iface,
                "desc" => "Set listening iface. ex: iface eth0",
              },
    "manual" => {
                "sub"  => \&sh_manual,
                "desc" => "Print detailed usage instructions",
              },
    "print" => {
                "sub"  => \&sh_print,
                "desc" => "Print a string",
               },
    "sniff" => {
                "sub"  => \&int_read_pkts,
                "desc" => "Sniff packets from iface. End with CTRL+C.",
              },
    "stats" => {
                "sub"  => \&int_pcap_stats,
                "desc" => "Report stats on the current listening iface.",
              },
    "scan" => {
                "sub"  => \&int_scan_host,
                "desc" => "tcp connect() scan a host. ex: scan 192.168.0.56",
              },
};

&init_network;

&read_nmap_sig_file("nmap-service-probes");

if ( scalar @ARGV ) {
    if ( -f $ARGV[0] ) {
        open(my $FH, "<", "$ARGV[0]") or &seppuku;
        foreach (<$FH>) {
            chomp;
            $internals->{"interrupt"} = 0;
            #if ( $_ !~ /^\s*(#.*)?$/ ) { 
                sh_readline($_);
            #}
        }
        close $FH;
    } else {
        $internals->{"interrupt"} = 0;
        sh_readline( join(' ',@ARGV) );
    }
    &seppuku;
}

print $environ->{"MOTD"},"\n";
print $environ->{"PROMPT"};

while (<STDIN>) {
    chomp;
    $internals->{"interrupt"} = 0;
        sh_readline($_);
    print $environ->{"PROMPT"};
}

print "\n";
&seppuku;

############################## Shell Subroutines ###############################

# sh_readline takes a line of input and does its' best to handle it properly.
# First it uses sh_parse_meta to replace all $variables with their values.
# Second it adds the sh_parse_meta'd line to the history.
# Third it would check to see if the line is attempting to break out to a real shell and run a command. At least, if that section were not currently commented out.
# Fourth it checks to see if the line is setting a variable. If so, it sets the variable and stops processing.
# Fifth it checks to see if the line is calling a builtin. If so, it runs the builtin with any options specified and then stops processing.
# Finally, it gives up and complains about the input, because it couldn't find anything to do with it.
sub sh_readline {
    my ($line) = @_;
    $line =~ s/#.*$//;
    $line = &sh_parse_meta("$line");
    if ( $line =~ /^\s*$/m ) {
        return;
    }

    my ($input,@args) = split(' ',$line);

    # Maintain history length
    if ( scalar @history >= $environ->{"HIST_SIZE"} ) {
        shift(@history);
    }
    push @history, $line;

    ### External commands disabled for now
    # External commands begin with !
    #if ( $line =~ /^!/m ) {
        #$line =~ s/^!//;
        #system( $line );
        #return;
    #}

    # Check for environ variables being set
    if ( $line =~ /^\w+?=.+$/m ) {
        (my $opt = $line) =~ s/^(\w+?)=.+$/$1/;
        (my $val = $line) =~ s/^\w+?=(.+)$/$1/;
        $environ->{"$opt"} = $val;
        return;
    }

    foreach my $builtin ( keys %$builtins ) {
        if ( "$input" eq "$builtin" ) {
            &{ $builtins->{"$builtin"}->{"sub"} }(@args);
            return;
        }
    }

    &warn_msg( "$input: unknown command" );
}

# Print basic information about all builtins
sub sh_help {
    print "Available commands:\n";
    foreach my $builtin ( sort keys %$builtins ) {
        printf "    %-10s %s\n",
            $builtin,
            $builtins->{"$builtin"}->{"desc"};
    }
    printf "MAGNI is using %s\n",
        Net::Pcap::pcap_lib_version();
}

sub sh_history {
    print join("\n", @history),"\n";
}

# Dump the manual to the screen.
sub sh_manual {
    if ( open(my $FH, "<", "$manual_file") ) {
        while (<$FH>) { print; }
    } else {
        &warn_msg("Could not read $manual_file");
    }
}

# Convert $variables to their values
sub sh_parse_meta {
    my ($line) = @_;
    # Load $variables into an array
    my @vars = $line =~ /(.?\$\w+)/g;
    # Uniq the array so we only operate on each $variable once
    @vars = &uniq(@vars);
    foreach my $var ( @vars ) {
        my $val;
        if ( $var =~ /^\\/ ) { next; }
        $var =~ s/.?\$//;
        if ( $environ->{"$var"} ) {
            $val = "$environ->{$var}";
        } else {
            $val = "";
        }
        # Replace non-escape $variables with their values
        $line =~ s/(?<!\\)\$$var\b/$val/g;
        # Replace \$variables with $variables (remove escapes)
        $line =~ s/\\\$$var\b/\$$var/g;
    }
    return $line;
}

# This is rather redundant.
sub sh_print {
    print "@_\n";
}

# Print the contents of environ to the screen.
sub sh_print_environ {
    foreach my $opt ( sort keys %$environ ) {
        printf "%s=%s\n",
            $opt,
            $environ->{"$opt"};
    }
}

############################# General Subroutines ##############################

# Print a list of each interface and its' IP and netmask, and list the currently listening interface.
sub int_iflist {
    foreach my $iface ( sort keys %{$internals->{"ifaces"}} ) {
        my $inet = "Unassigned";
        my $mask = "Unassigned";
        my $err;
        Net::Pcap::pcap_lookupnet( $iface, \$inet, \$mask, \$err);
        if ( "$inet" ne "Unassigned" ) { 
            $inet = inet_ntoa(pack "N", $inet);
        }
        if ( "$mask" ne "Unassigned" ) { 
            $mask = inet_ntoa(pack "N", $mask);
        }
        if ( $err ) { &warn_msg("$err"); }
        printf "%10s  inet:%s  mask:%s\n", 
            $iface, $inet, $mask;
    }
    if ( "$internals->{capture_iface_name}" ne "" ) {
        print "Currently listening on ",$internals->{"capture_iface_name"},"\n";
    } else {
        print "Not currently listening on any interface.\n";
    }
}

# Print stats for the current sniffing interface
sub int_pcap_stats {
    if ( "$internals->{capture_iface_name}" ne "" ) {
        my $stats = {};
        my $link = Net::Pcap::pcap_datalink( $internals->{"capture_iface"} );
        Net::Pcap::pcap_stats( $internals->{"capture_iface"}, \%$stats );
        print $internals->{"capture_iface_name"},"\n";
        printf "  linktype: %s\n",
            Net::Pcap::pcap_datalink_val_to_description($link);
        printf "  rx:%d  pcap_drop:%d  if_drop:%d\n",
            $stats->{"ps_recv"},
            $stats->{"ps_drop"},
            $stats->{"ps_ifdrop"};
        printf "  snaplen: %d\n",
            Net::Pcap::pcap_snapshot( $internals->{"capture_iface"} );
    } else {
        print "Not listening on any interface.\n";
    }
}

# Given a packet header and its' contents, build a NetPacket object for that packet
# Once built, hand it off to either int_print_packet  or to int_service_lookup, depending on the current setup.
sub int_process_pkt {
    my ($pkt_hdr, $raw) = @_;
    my $pkt = {};
    $pkt->{"ether"} = NetPacket::Ethernet->decode($raw);
    if ( $pkt->{"ether"}->{"type"} eq NetPacket::Ethernet::ETH_TYPE_IP ) {
        $pkt->{"ip"} = NetPacket::IP->decode($pkt->{"ether"}->{"data"});
        $pkt->{"proto"} = 
            getprotobynumber( $pkt->{"ip"}->{"proto"});
    } elsif ( $pkt->{"ether"}->{"type"} eq NetPacket::Ethernet::ETH_TYPE_ARP ) {
        $pkt->{"arp"} = NetPacket::ARP->decode($pkt->{"ether"}->{"data"});
    }

    if ( ! $pkt->{"proto"} ) { $pkt->{"proto"} = ""; }

    if ( $pkt->{"proto"} eq "tcp" ) {
        $pkt->{"tcp"} = NetPacket::TCP->decode($pkt->{"ip"}->{"data"});
    } elsif ( $pkt->{"proto"} eq "udp" ) {
        $pkt->{"udp"} = NetPacket::UDP->decode($pkt->{"ip"}->{"data"});
    } elsif ($pkt->{"proto"} eq "icmp" ) {
        $pkt->{"icmp"} = NetPacket::ICMP->decode($pkt->{"ip"}->{"data"});
    } elsif ($pkt->{"proto"} eq "igmp" ) {
        $pkt->{"igmp"} = NetPacket::IGMP->decode($pkt->{"ip"}->{"data"});
    }

    if ( $environ->{"PRINT_PACKETS"} ) {
        &int_print_packet($pkt_hdr,$pkt);
    } elsif ( $environ->{"SERVICE_DETECT"} ) {
        my $data = "";
        my $src = "";
        my $src_p = "";
        if ( $pkt->{"ip"} ) {
            $src = $pkt->{"ip"}->{"src_ip"};
            if ( $pkt->{"tcp"} ) {
                $data = "$pkt->{tcp}->{data}";
                $src_p = "$pkt->{tcp}->{src_port}";
            } elsif ( $pkt->{"udp"} ) {
                $data = "$pkt->{udp}->{data}";
                $src_p = "$pkt->{udp}->{src_port}";
            } elsif ( $pkt->{"icmp"} ) {
                $data = "$pkt->{icmp}->{data}";
            } elsif ( $pkt->{"igmp"} ) {
                $data = "$pkt->{igmp}->{data}";
            }
        }

        if ( "$data" ne "" ) {
            my $service_info = &int_service_lookup($data);
            if ( $service_info ) {
                printf "%s%s %s\n",
                    $src,
                    ($src_p)? ":$src_p" : "",
                    $service_info;
            }
        }
    }
}

# Print the various fields of a packet, depending on the type of packet it is.
# usage: &int_print_packet( $packet_header, $packet );
sub int_print_packet {
    my ($pkt_hdr,$pkt) = @_;    

    # Timestamp
    printf "%.6f ",
        "$pkt_hdr->{tv_sec}.$pkt_hdr->{tv_usec}";
    if ( $pkt->{"ip"} ) {
        # Source IP, port and MAC
        print $pkt->{"ip"}->{"src_ip"};
        if ( $pkt->{"tcp"} ) {
            printf ":%d ",$pkt->{"tcp"}->{"src_port"};
        } elsif ( $pkt->{"udp"} ) {
            printf ":%d ",$pkt->{"udp"}->{"src_port"};
        } else {
            print " ";
        }
        printf "(%s) ",&format_mac( $pkt->{"ether"}->{"src_mac"} );

        print "-> ";

        # Destination IP, port and MAC
        print $pkt->{"ip"}->{"dest_ip"};
        if ( $pkt->{"tcp"} ) {
            printf ":%d ",$pkt->{"tcp"}->{"dest_port"};
        } elsif ( $pkt->{"udp"} ) {
            printf ":%d ",$pkt->{"udp"}->{"dest_port"};
        } else {
            print " ";
        }
        printf "(%s) ",&format_mac( $pkt->{"ether"}->{"dest_mac"} );

        print "$pkt->{proto} ";
        printf "id:%d ",$pkt->{"ip"}->{"id"};
        printf "len:%d ",$pkt_hdr->{"len"};
        printf "caplen:%d ",$pkt_hdr->{"caplen"};
        printf "hlen:%d ",$pkt->{"ip"}->{"hlen"};
        printf "ttl:%d ",$pkt->{"ip"}->{"ttl"};
        if ( $pkt->{"tcp"} ) {
            printf "acknum:%d ",$pkt->{"tcp"}->{"acknum"};
            printf "seqnum:%d ",$pkt->{"tcp"}->{"seqnum"};
            printf "winsize:%d ",$pkt->{"tcp"}->{"winsize"};
            printf "urg:%d ",$pkt->{"tcp"}->{"urg"};
            &int_print_pkt_data( "$pkt->{tcp}->{data}" );
        } elsif ( $pkt->{"udp"} ) {
            printf "cksum:%d ",$pkt->{"udp"}->{"cksum"};
            &int_print_pkt_data( "$pkt->{udp}->{data}" );
        } elsif ( $pkt->{"icmp"} ) {
            printf "type:%s ", $pkt->{"icmp"}->{"type"};
            printf "code:%s ", $pkt->{"icmp"}->{"code"};
            printf "cksum:%s ", $pkt->{"icmp"}->{"cksum"};
            &int_print_pkt_data( "$pkt->{icmp}->{data}" );
        } elsif ( $pkt->{"igmp"} ) {
            printf "version:%s ", $pkt->{"igmp"}->{"version"};
            printf "type:%s ", $pkt->{"igmp"}->{"type"};
            printf "len:%s ", $pkt->{"igmp"}->{"len"};
            printf "subtype:%s ", $pkt->{"igmp"}->{"subtype"};
            printf "cksum:%s ", $pkt->{"igmp"}->{"cksum"};
            printf "group_addr:%s ", $pkt->{"igmp"}->{"group_addr"};
            &int_print_pkt_data( "$pkt->{igmp}->{data}" );
        }
    } elsif ( $pkt->{"arp"} ) {
        if ( $pkt->{"arp"}->{"opcode"} eq NetPacket::ARP::ARP_OPCODE_REQUEST ) {
            print "arp-request ";
        } elsif ( $pkt->{"arp"}->{"opcode"} eq NetPacket::ARP::ARP_OPCODE_REPLY ) {
            print "arp-reply ";
        } elsif ( $pkt->{"arp"}->{"opcode"} eq NetPacket::ARP::RARP_OPCODE_REQUEST ) {
            print "rarp-request ";
        } elsif ( $pkt->{"arp"}->{"opcode"} eq NetPacket::ARP::RARP_OPCODE_REPLY ) {
            print "rarp-reply ";
        }
        printf "htype:%s ", $pkt->{"arp"}->{"htype"};
        printf "ptype:%s ", $pkt->{"arp"}->{"proto"};
        printf "hlen:%s ", $pkt->{"arp"}->{"hlen"};
        printf "plen:%s ", $pkt->{"arp"}->{"plen"};

        printf "sha:%s ", &format_mac( $pkt->{"arp"}->{"sha"} );
        # If this is an ethernet address, print it
        if ( $pkt->{"arp"}->{"proto"} == 2048 ) {
            printf "spa:%s ", inet_ntoa(pack "N", hex $pkt->{"arp"}->{"spa"} );
        } else {
            printf "spa:",$pkt->{"arp"}->{"spa"};
        }

        printf "tha:%s ", &format_mac( $pkt->{"arp"}->{"tha"} );
        # If this is an ethernet address, print it
        if ( $pkt->{"arp"}->{"proto"} == 2048 ) {
            printf "tpa:%s ", inet_ntoa(pack "N", hex $pkt->{"arp"}->{"tpa"} );
        } else {
            printf "tpa:",$pkt->{"arp"}->{"tpa"};
        }
    } else {
        printf "len:%d caplen:%d ",
            $pkt_hdr->{"len"},
            $pkt_hdr->{"caplen"};
        printf "(%s) -> (%s) ",
            &format_mac( $pkt->{"ether"}->{"src_mac"} ),
            &format_mac( $pkt->{"ether"}->{"dest_mac"} );
    }
    print "\n";
}

# Print the data content of a packet, replacing nonprintable characters with '.'
sub int_print_pkt_data {
    my ($data) = @_;
    if ( $environ->{"PRINT_DATA"} ) {
        $data =~ s/[[:^print:]]/./g;
        print "data:$data ";
    }
}

# Capture packets on the current sniffing interface
# Calls int_process_pkt to process and print captured packets
sub int_read_pkts {
    my $pkt_ct = 0;
    $internals->{"interrupt"} = 0;
    if ( "$internals->{capture_iface_name}" eq "" ) {
        print "Not listening on any interface.\n";
        return;
    }
    while ( $internals->{"interrupt"} == 0 ) {
        my $pkt_hdr = {};
        my $pkt;
        my $retval = Net::Pcap::pcap_next_ex(
            $internals->{"capture_iface"},
            \%$pkt_hdr,
            \$pkt);

        if ( $retval == 1 ) {
            $pkt_ct++;
            &int_process_pkt( $pkt_hdr, $pkt );
        } elsif ( $retval == 0 ) {
            print "Connection timeout\n";
        } elsif ( $retval == -1 ) {
            printf "Error reading packet: %s\n",
                Net::Pcap::pcap__geterr( $internals->{"capture_iface"} );
        } elsif ( $retval == -2 ) {
            print "No more packets to read\n";
            last;
        } else {
            &warn_msg("Weird pcap return value");
        }
    }
    $internals->{"interrupt"} = 0;
    print "Captured $pkt_ct packets\n";
}

# TCP connect() scan a host on given ports
# If no ports are specified, scan ports 1-1024
# usage: &scan_host( $host, @ports_to_scan );
sub int_scan_host {
    my ($host,@ports) = @_;
    my $iaddr = inet_aton($host);
    my $open = 0;
    if ( ! scalar @ports ) {
        @ports = 1 .. 1024;
    }
    print "Scanning $host\n";
    foreach my $port_no ( @ports ) {
        if ( $internals->{"interrupt"} ) {
            last;
        }
        my $paddr = sockaddr_in( $port_no, $iaddr );
        my $proto = getprotobyname("tcp");
        socket(my $SOCK, PF_INET, SOCK_STREAM, $proto);
        if ( connect($SOCK, $paddr) ) {
            my $service_info = "";
            if ( $environ->{"SERVICE_DETECT"} ) {
                eval {
                    local $SIG{ALRM} = sub { die "Timeout\n"; };
                    alarm $environ->{"TIMEOUT"};
                    #while (<$SOCK>) {
                        #$service_info .= &int_service_lookup($_);
                    #}
                    print $SOCK "\n";
                    my $line = <$SOCK>;
                    $service_info .= &int_service_lookup($line);
                    alarm 0;
                };
            }
            print "$host:$port_no open $service_info\n";
            $open++;
            close($SOCK);
        }
    }
    $internals->{"interrupt"} = 0;
    printf "%d port%s open, %d closed\n",
        $open,
        ($open==1)? "" : "s",
        scalar @ports - $open;
}

# Set the interface that will be used for sniffing
# usage: &int_set_iface( $interface );
sub int_set_iface {
    my ($iface) = @_;
    my $err;
    if ( ! defined $iface ) {
        print "No interface specified!\n";
        return;
    }
    if ( "$internals->{capture_iface_name}" ) {
        Net::Pcap::pcap_close( $internals->{"capture_iface_name"} );
    }
    if ( $internals->{"ifaces"}->{"$iface"} ) {
        $internals->{"capture_iface"} = 
            Net::Pcap::pcap_open_live(
                $iface,
                $environ->{"SNAPLEN"},
                $environ->{"PROMISCUOUS"},
                $environ->{"TIMEOUT"},
                \$err);
        if ( $err ) {
            &warn_msg("Could not read from $iface: $err");
            return;
        }
        $internals->{"capture_iface_name"} = $iface;
        print "Now listening on $iface\n";
    } else {
        print "$iface is not a valid interface\n";
    }
}

# Given $data, see if it matches any of our service signatures
# usage: &int_service_lookup( $data );
sub int_service_lookup {
    my ($data) = @_;
    my @return = ();
    study $data;
    foreach my $service ( keys %$service_sigs ) {
        foreach my $sig ( @{$service_sigs->{"$service"}} ) {
            if ( $data =~ $sig ) {
                push @return, $service;
            }
        }
    }
    return join(",", &uniq(sort @return) );
}

# Find all valid interfaces to sniff on
sub init_network {
    my $err;
    Net::Pcap::pcap_findalldevs( \%{$internals->{"ifaces"}}, \$err);
    # 'any' is not an actual interface. Though it is a valid value to use when listening, don't add it to the list of interfaces.
    delete $internals->{"ifaces"}->{"any"};
    if ( $err ) {
        &warn_msg("$err");
        &seppuku;
    }
}

sub ctrl_c {
    $internals->{"interrupt"} = 1;
    print "\n", $environ->{"PROMPT"}; 
};

# Change a non-delimited MAC into a delimited MAC
# ex: 01234567890a -> 01:23:45:67:89:0a
# usage: &format_mac( $mac );
sub format_mac {
    my ($mac) = @_;
    $mac =~ s/(?<![0-9a-f]{2}:)([0-9a-f]{2})/$1:/g;
    $mac =~ s/:$//;
    return $mac;
}

# Read nmap-service-probes file and load the probes into the signature database
# usage: &read_nmap_sig_file( $path_to_signature_file );
sub read_nmap_sig_file {
    my ($file) = @_;
    my $err;
    open (my $FH, "<", "$file") or $err = 1;
    if ( $err ) {
        &warn_msg("Could not read service probe file: $file!");
        return;
    }
    foreach my $line (<$FH>) {
        chomp $line;
        # All signature lines begin with 'match'
        if ( $line !~ /^match/ ) {
            next;
        }
        (my $service = $line) =~ s/^match (.+?) .*$/$1/;
        (my $regex = $line) =~ s/^match .+? m(.)(.+?)\1.*$/$2/;

        # Make sure this is a valid regular expression before adding it.
        eval {
            no warnings 'all';
            $regex =  qr|$regex|mis;
        };
        if ( "$@" eq "" ) {
            push( @{ $service_sigs->{"$service"} }, qr|$regex|mis );
        }
    }
}

sub sig_exit {
    my ($sig) = @_;
    &warn_msg("Caught SIG$SIG! Exiting...");
    &seppuku;
}

# Die an honorable death
# Close open pcap interfaces and exit
sub seppuku {
    if ( "$internals->{capture_iface_name}" ne "" ) {
        Net::Pcap::pcap_close( $internals->{"capture_iface"} );
    }
    exit;
}

# Return the unique values of an array
# usage: @unique_values = &uniq( @non_unique_values );
sub uniq { 
    my (@ary) = @_;
    my %u = map {$_=>1} @ary;
    return keys %u;
}

sub warn_msg {
    my (@msg) = @_;
    print STDERR "$program_base_name: @msg\n";
}
