# MAGNI - Simple network sniffer and scanner
# Copyright (C) 2010  Ben Rosenberg
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package Magni::Network;

use strict;
use Magni;
use Magni qw( $internals );
use Magni::Shell qw( $environ );
use Net::DNS;
use Net::Pcap;
use NetPacket::ARP;
use NetPacket::Ethernet;
use NetPacket::ICMP;
use NetPacket::IGMP;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use Socket;

# Print a list of each interface and its' IP and netmask, and list the currently listening interface.
sub print_iflist {
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
sub print_pcap_stats {
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
# Once built, hand it off to $post_process_action subroutine.
sub process_pkt {
    my ($pkt_hdr, $raw, $post_process_action) = @_;
    #my ($pkt_hdr, $raw) = @_;
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

    &{ $post_process_action }($pkt_hdr,$pkt);
}

# Extract data portion of packet.
# This is a separate subrotuine because one day there should be something more
#  than &print_service_info for handling service detection output.
sub pre_service_info {
    my ($pkt_hdr,$pkt) = @_;
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
            &print_service( $service_info );
        }
    }
}

sub print_service_info {
    my ( $service_info, $src, $src_p ) = @_;
    printf "%s%s %s\n",
        $src,
        ($src_p)? ":$src_p" : "",
        $service_info;
}

# Print the various fields of a packet, depending on the type of packet it is.
# Works on a NetPacket packet
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

sub write_packet {
    my ($pkt_hdr,$pkt) = @_;    
    Net::Pcap::pcap_dump( $internals->{"pcap_output"}, $pkt_hdr, $pkt );
}

# Capture packets on the current sniffing interface
# Calls process_pkt to process and print captured packets
sub sniff_pkts {
    my $pkt_ct = 0;
    my $post_process_action = sub {
        print "Capturing packets and doing nothing with them! Stop this with CTRL+C\n";
    };
    if ( $environ->{"PRINT_PACKETS"} ) {
        $post_process_action = \&print_packet;
    } elsif ( $environ->{"WRITE_PACKETS"} && 
              defined $internals->{"pcap_output"} ) {
        $post_process_action = \&write_packet;
    } elsif ( $environ->{"SERVICE_DETECT"} ) {
        $post_process_action = \&pre_service_info;
    }
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
            &process_pkt( $pkt_hdr, $pkt, $post_process_action );
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
    print "Processed $pkt_ct packets\n";
}

# TCP connect() scan a host on given ports
# If no ports are specified, scan ports 1-1024
# usage: &scan_host( $host, @ports_to_scan );
sub scan_host {
    my ($host,$port_list) = @_;
    my $iaddr = inet_aton($host);
    my @ports;
    my $open = 0;
    if ( defined $port_list ) {
        @ports = &parse_port_list( $port_list );
    }
    if ( ! scalar @ports ) {
        @ports = 1 .. 1024;
    }
    print "Scanning $host\n";
    foreach my $port_no ( @ports ) {
        if ( $internals->{"interrupt"} ) {
            $internals->{"interrupt"} = 0;
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
                    alarm 0;
                    $service_info .= service_lookup($line);
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
    if ( defined $internals->{"capture_iface"} ) {
        &close_iface;
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

# Stop listening on an iface
sub close_iface {
    if ( defined $internals->{"capture_iface"} ) {
        Net::Pcap::pcap_close( $internals->{"capture_iface"} );
        printf "No longer listening on %s\n",$internals->{"capture_iface_name"};
        $internals->{"capture_iface"} = undef;
        $internals->{"capture_iface_name"} = undef;
        # For now pcap output files are associated with ifaces.
        if ( defined $internals->{"pcap_output"} ) {
            &close_pcap_output;
        }
    } else {
        print "Not listening on an interface.\n";
    }
}

# Open a file to write pcap dumps to
# TODO: Do we really need to use pcap_dump_open? Seems like doing this by hand
#  would be better. Then we wouldn't need to associate the dump file with an
#  interface, which seems unnecessary.
sub set_pcap_output {
    my ($file) = @_;
    if ( defined $internals->{"capture_iface"} ) {
        $internals->{"pcap_output"} = Net::Pcap::pcap_dump_open(
                                        $internals->{"capture_iface"},
                                        $file
                                      );
        if ( ! defined $internals->{"pcap_output"} ) {
            &warn_msg("Could not write to file $file");
            return;
        }
        $internals->{"pcap_output_name"} = "$file";
        printf "Opened file $file for writing, and associated it with %s\n",
            $internals->{"capture_iface_name"};
    } else {
        print "Must be listening on an interface to start a pcap dump\n";
    }
}

# Close a pcap file that is open for writing
sub close_pcap_output {
    if ( defined $internals->{"pcap_output"} ) {
        Net::Pcap::pcap_dump_flush( $internals->{"pcap_output"} );
        Net::Pcap::pcap_dump_close( $internals->{"pcap_output"} );
        print "No longer writing to %s", $internals->{"pcap_output_name"};
        $internals->{"pcap_output_name"} = undef;
        $internals->{"pcap_output"} = undef;
    } else {
        print "Not currently writing an output file\n";
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

sub host_lookup {
    my (@hosts) = @_;
    foreach my $host ( Magni::uniq(@hosts) ) {
        my @res = &resolve_host($host);
        if ( scalar @res ) {
            print "$host = ",pop @res;
            foreach ( @res ) {
                print " $_";
            }
            print "\n";
        } else {
            print STDERR "Can not find $host\n";
        }
    }
}

# If given an IPv4 address, return the PTR record for the host.
# If given a hostname, return the A record for the host.
sub resolve_host {
    my ($host) = @_;
    my $r = Net::DNS::Resolver->new;
    my $q = $r->search("$host");
    my @retval;
    if ( $q ) {
        if ( &valid_ipv4($host) ) {
            foreach my $rr ( $q->answer ) {
                if ( $rr->type eq "PTR" && defined $rr->ptrdname ) {
                    push @retval,$rr->ptrdname;
                }
            }
        } else {
            foreach my $rr ( $q->answer ) {
                if ( $rr->type eq "A" && defined $rr->address ) {
                    push @retval,$rr->address;
                }
            }
        }
    }
    return @retval;
}

# Check to see if input is a valid IPv4 address
sub valid_ipv4 {
    my ($in) = @_;
    if ( $in =~ /([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/m &&
         defined $1 && defined $2 && defined $3 && defined $4 && 
         $1 >= 0 && $1 <= 255 &&
         $2 >= 0 && $2 <= 255 &&
         $3 >= 0 && $3 <= 255 &&
         $4 >= 0 && $4 <= 255 ) {
        return 1;
    } else {
        return 0;
    }
}

sub parse_port_list {
    my ($port_list) = @_;
    my @retval;
    foreach ( split( ',', $port_list ) ) {
        if ( /([0-9]+)-([0-9]+)/m ) {
            push @retval, ($1 .. $2);
        } else {
            push @retval, $_;
        }
    }
    return Magni::uniq(@retval);
}

1;
