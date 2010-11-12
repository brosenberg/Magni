package Magni::Network;

use strict;
use Magni;
use Magni qw( $internals );
use Magni::Shell qw( $environ );
use Net::Pcap;
use NetPacket::ARP;
use NetPacket::Ethernet;
use NetPacket::ICMP;
use NetPacket::IGMP;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use Socket;

############################# General Subroutines ##############################

# Print a list of each interface and its' IP and netmask, and list the currently listening interface.
sub iflist {
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
        #if ( $err ) { &warn_msg("$err"); }
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
sub pcap_stats {
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
# Once built, hand it off to either print_packet  or toservice_lookup, depending on the current setup.
sub process_pkt {
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
        &print_packet($pkt_hdr,$pkt);
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
            my $service_info = service_lookup($data);
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
# usage: print_packet( $packet_header, $packet );
sub print_packet {
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
        printf "(%s) ",Magni::format_mac( $pkt->{"ether"}->{"src_mac"} );

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
        printf "(%s) ",Magni::format_mac( $pkt->{"ether"}->{"dest_mac"} );

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
            &print_pkt_data( "$pkt->{tcp}->{data}" );
        } elsif ( $pkt->{"udp"} ) {
            printf "cksum:%d ",$pkt->{"udp"}->{"cksum"};
            &print_pkt_data( "$pkt->{udp}->{data}" );
        } elsif ( $pkt->{"icmp"} ) {
            printf "type:%s ", $pkt->{"icmp"}->{"type"};
            printf "code:%s ", $pkt->{"icmp"}->{"code"};
            printf "cksum:%s ", $pkt->{"icmp"}->{"cksum"};
            &print_pkt_data( "$pkt->{icmp}->{data}" );
        } elsif ( $pkt->{"igmp"} ) {
            printf "version:%s ", $pkt->{"igmp"}->{"version"};
            printf "type:%s ", $pkt->{"igmp"}->{"type"};
            printf "len:%s ", $pkt->{"igmp"}->{"len"};
            printf "subtype:%s ", $pkt->{"igmp"}->{"subtype"};
            printf "cksum:%s ", $pkt->{"igmp"}->{"cksum"};
            printf "group_addr:%s ", $pkt->{"igmp"}->{"group_addr"};
            &print_pkt_data( "$pkt->{igmp}->{data}" );
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

        printf "sha:%s ", Magni::format_mac( $pkt->{"arp"}->{"sha"} );
        # If this is an ethernet address, print it
        if ( $pkt->{"arp"}->{"proto"} == 2048 ) {
            printf "spa:%s ", inet_ntoa(pack "N", hex $pkt->{"arp"}->{"spa"} );
        } else {
            printf "spa:",$pkt->{"arp"}->{"spa"};
        }

        printf "tha:%s ", Magni::format_mac( $pkt->{"arp"}->{"tha"} );
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
            Magni::format_mac( $pkt->{"ether"}->{"src_mac"} ),
            Magni::format_mac( $pkt->{"ether"}->{"dest_mac"} );
    }
    print "\n";
}

# Print the data content of a packet, replacing nonprintable characters with '.'
sub print_pkt_data {
    my ($data) = @_;
    if ( $environ->{"PRINT_DATA"} ) {
        $data =~ s/[[:^print:]]/./g;
        print "data:$data ";
    }
}

# Capture packets on the current sniffing interface
# Calls process_pkt to process and print captured packets
sub read_pkts {
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
            &process_pkt( $pkt_hdr, $pkt );
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
sub scan_host {
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
                        #$service_info .= service_lookup($_);
                    #}
                    print $SOCK "\n";
                    my $line = <$SOCK>;
                    $service_info .= service_lookup($line);
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
# usage: set_iface( $interface );
sub set_iface {
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

# Find all valid interfaces to sniff on
sub init_network {
    my $err;
    Net::Pcap::pcap_findalldevs( \%{$internals->{"ifaces"}}, \$err);
    # 'any' is not an actual interface. Though it is a valid value to use when listening, don't add it to the list of interfaces.
    delete $internals->{"ifaces"}->{"any"};
    if ( $err ) {
        &warn_msg("$err");
    }
}

1;
