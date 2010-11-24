#!/usr/bin/perl -w
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

use strict;
# Or wherever you put the perl modules, if you do not install them.
#use lib "/home/ben/Magni";
use Magni;
use Magni::Shell qw( $environ $builtins );
use Magni::Network;

my $program_name = eval { (caller)[1]; };
(my $program_base_name = $program_name) =~ s/^.*\///;
(my $program_dir = $program_name) =~ s/^(.*)\/.+?$/$1/;

$|=1;

$SIG{HUP} = \&Magni::sig_exit;
$SIG{INT} = sub { 
        Magni::set_ctrl_c;
        print "\n";
        Magni::Shell::sh_print_prompt;
    };
$SIG{QUIT} = \&Magni::sig_exit;
$SIG{TERM} = \&Magni::sig_exit;

$environ->{"PROMISCUOUS"}    =     1;
$environ->{"SNAPLEN"}        =  1500; # bytes
$environ->{"TIMEOUT"}        =   500; # milliseconds
$environ->{"PRINT_DATA"}     =     1;
$environ->{"PRINT_PACKETS"}  =     1;
$environ->{"WRITE_PACKETS"}  =     0;
$environ->{"SERVICE_DETECT"} =     0;

$builtins->{"close"} = {
    "sub"  => \&Magni::Network::close_pcap_output,
    "desc" => "Close a pcap file for writing",
  };
$builtins->{"iflist"} = {
    "sub" => \&Magni::Network::print_iflist,
    "desc" => "List available ifaces",
  };
$builtins->{"listen"} = {
    "sub"  => \&Magni::Network::set_iface,
    "desc" => "Set listening iface. ex: iface eth0",
  };
$builtins->{"lookup"} = {
    "sub"  => \&Magni::Network::host_lookup,
    "desc" => "Perform DNS lookup on a host. ex: lookup example.com",
  };
$builtins->{"open"} = {
    "sub"  => \&Magni::Network::set_pcap_output,
    "desc" => "Open a pcap file for writing. ex: open dump.pcap",
  };
$builtins->{"sniff"} = {
    "sub"  => \&Magni::Network::sniff_pkts,
    "desc" => "Sniff packets from iface. End with CTRL+C.",
  };
$builtins->{"stats"} = {
    "sub"  => \&Magni::Network::print_pcap_stats,
    "desc" => "Report stats on the current listening iface.",
  };
$builtins->{"stop"} = {
    "sub"  => \&Magni::Network::close_iface,
    "desc" => "Stop listening on current iface",
  };
$builtins->{"scan"} = {
    "sub"  => \&Magni::Network::scan_host,
    "desc" => "connect() scan a host. ex: scan 192.168.0.56",
    "man"  => "$program_dir/Manual/scan",
  };


Magni::Network::init_network;

if ( scalar @ARGV ) {
    if ( -f $ARGV[0] ) {
        open(my $FH, "<", "$ARGV[0]") or die;
        foreach (<$FH>) {
            Magni::Shell::get_input($_);
        }
        close $FH;
    } else {
        Magni::Shell::get_input( join(' ',@ARGV) );
    }
    exit;
}

Magni::Shell::sh_print_motd;
Magni::Shell::sh_print_prompt;

while (<STDIN>) {
    Magni::Shell::get_input($_);
    Magni::Shell::sh_print_prompt;
}

print "\n";
exit;
