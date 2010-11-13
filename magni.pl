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

$builtins->{"iflist"} = {
    "sub" => \&Magni::Network::iflist,
    "desc" => "List available ifaces",
  };
$builtins->{"listen"} = {
    "sub"  => \&Magni::Network::set_iface,
    "desc" => "Set listening iface. ex: iface eth0",
  };
$builtins->{"sniff"} = {
    "sub"  => \&Magni::Network::read_pkts,
    "desc" => "Sniff packets from iface. End with CTRL+C.",
  };
$builtins->{"stats"} = {
    "sub"  => \&Magni::Network::pcap_stats,
    "desc" => "Report stats on the current listening iface.",
  };
$builtins->{"scan"} = {
    "sub"  => \&Magni::Network::scan_host,
    "desc" => "tcp connect() scan a host. ex: scan 192.168.0.56",
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
