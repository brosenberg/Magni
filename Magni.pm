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


package Magni;

use strict;
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw( warn_msg );
our @EXPORT_OK = qw( $internals );
use Net::Pcap;

# Non-user definable options
our $internals = {
    "capture_iface_name" => "",
    "capture_iface" => "",
    "ifaces" => {},
    "interrupt" => 0,
};

sub clear_ctrl_c {
        $internals->{"interrupt"} = 0;
}

sub set_ctrl_c {
    $internals->{"interrupt"} = 1;
}

# Change a non-delimited MAC into a delimited MAC
# ex: 01234567890a -> 01:23:45:67:89:0a
# usage: &format_mac( $mac );
sub format_mac {
    my ($mac) = @_;
    $mac =~ s/(?<![0-9a-f]{2}:)([0-9a-f]{2})/$1:/g;
    $mac =~ s/:$//;
    return $mac;
}

sub sig_exit {
    my ($sig) = @_;
    &warn_msg("Caught SIG$SIG! Exiting...");
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
    print STDERR "error: @msg\n";
}

END {
    if ( "$internals->{capture_iface_name}" ne "" ) {
        Net::Pcap::pcap_close( $internals->{"capture_iface"} );
    }
}
