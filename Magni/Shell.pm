package Magni::Shell;

use strict;
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw( $environ $builtins );
use Magni;

my @history; # Shell history
my $manual_file = "";

# User definable options
our $environ = {
    "MOTD" => "What do you require of MAGNI?",
    "PROMPT" => "MAGNI> ",
    "HIST_SIZE" => 500,
    "PROMISCUOUS" => 1,
    "SNAPLEN" => 1024,
    "TIMEOUT" => 20,
    "PRINT_DATA" => 1,
    "PRINT_PACKETS" => 1,
    "SERVICE_DETECT" => 0,
};

# Builtin commands. The key is the name of the command, the hash it points to contains "sub" which is the subroutine that will be run when the builtin is run, and "desc" a brief description of the command.
our $builtins = {
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
                "sub"  => sub { exit; },
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
    #"iflist" => {
                #"sub"  => \iflist,
                #"desc" => "List available ifaces",
              #},
    #"listen" => {
                #"sub"  => \set_iface,
                #"desc" => "Set listening iface. ex: listen eth0",
              #},
    "readme" => {
                "sub"  => \&sh_readme,
                "desc" => "Print detailed usage instructions",
              },
    "print" => {
                "sub"  => \&sh_print,
                "desc" => "Print a string",
               },
    #"sniff" => {
                #"sub"  => \read_pkts,
                #"desc" => "Sniff packets from iface. End with CTRL+C.",
              #},
    #"stats" => {
                #"sub"  => \pcap_stats,
                #"desc" => "Report stats on the current listening iface.",
              #},
    #"scan" => {
                #"sub"  => \scan_host,
                #"desc" => "tcp connect() scan a host. ex: scan 192.168.0.56",
              #},
};

############################## Shell Subroutines ###############################

sub get_input {
    my ($input) = @_;
    chomp $input;
    Magni::clear_ctrl_c;
    &sh_readline($input);
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

# Convert $variables to their values
sub sh_parse_meta {
    my ($line) = @_;
    # Load $variables into an array
    my @vars = $line =~ /(.?\$\w+)/g;
    # Uniq the array so we only operate on each $variable once
    @vars = Magni::uniq(@vars);
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

sub sh_print_motd {
    print $environ->{"MOTD"},"\n";
}

sub sh_print_prompt {
    print $environ->{"PROMPT"};
}

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

    &warn_msg("$input: unknown command");
}

# Dump the manual to the screen.
sub sh_readme {
    if ( open(my $FH, "<", "$manual_file") ) {
        while (<$FH>) { print; }
    } else {
        Magni::warn_msg("Could not read readme file \"$manual_file\"");
    }
}

1;
