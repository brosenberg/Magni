# MAGNI v0.1
# Very simple shell based network probing and monitoring tool.

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
