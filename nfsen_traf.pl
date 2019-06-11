#!/usr/bin/perl -W
use Modern::Perl;
use Time::HiRes;
use Net::NfDump;
use DBI;
use NetAddr::IP;
my $start    = Time::HiRes::gettimeofday();
my $base_dir = '/usr/local/var/nfsen/profiles-data/live/CCU/';
my $dir      = $ARGV[0];                                         #dirs for parse

my $files_dir  = $base_dir . $dir;
my $script_dir = '/var/www/XXXXXXX/XXXXXX/';
my $FILTER_IN  = '(
( (
  (ident CCU) and (OUT IF 110))
  or ((ident CCU) and (OUT IF 29))
  or ((ident CCU) and (OUT IF 48))
) ) and (bytes > 500) and (bps > 30)';
my $FILTER_OUT = '(
(
  (ident CCU) and (IN IF 33))
  or ((ident CCU) and (IN IF 32))
  or ((ident CCU) and (IN IF 30))
  or ((ident CCU) and (IN IF 49))
  or ((ident CCU) and (IN IF 51))
  or ((ident CCU) and (IN IF 62))
  or ((ident CCU) and (IN IF 65))
  or ((ident CCU) and (IN IF 53))
  or ((ident CCU) and (IN IF 87))
  or ((ident CCU) and (IN IF 31))
  or ((ident CCU) and (IN IF 85))
  or ((ident CCU) and (IN IF 117))
)
and (bytes > 500) and (bps > 30)';

sub ora_reconnect {
    $ENV{'NLS_LANG'}        = "AMERICAN_AMERICA.AL32UTF8";
    $ENV{'NLS_NCHAR'}       = "AL32UTF8";
    $ENV{'ORACLE_HOME'}     = "/usr/lib/oracle/11.2/client64";
    $ENV{'LD_LIBRARY_PATH'} = "/usr/lib/oracle/11.2/client64/lib";
    my $db     = '127.127.127.127';
    my $dbsid  = 'xxx_xxx';
    my $dbuser = 'xxx_xxx';
    my $dbpass = 'XxxXxxxXX';
    my $dbh;
    eval {
        $dbh = DBI->connect(
            "dbi:Oracle:host=$db;sid=$dbsid",
            $dbuser, $dbpass,
            {
                ora_ncharset  => 'AL32UTF8',
                ora_charset   => 'AL32UTF8',
                RaiseError    => 1,
                PrintError    => 1,
                ora_check_sql => 0
            }
        ) or die $DBI::errstr;
    };

    if ($@) {
        say STDERR "$@";
        return 0;
    }
    $dbh->{FetchHashKeyName} = 'NAME_lc';
    $dbh->{AutoCommit}       = 0;
    return $dbh;
}
my $dbh = ora_reconnect();

my $proc = `ps ax | grep "traf4.pl $dir" | grep -v grep`;
chomp($proc);
my $i = 0;
while ( $proc =~ /traf/g ) {
    $i++;
}
say "running scripts: $i";

if ( $i < 2 ) {

    #$db->rollback;
    my $files = `ssh oracle\@XXXXXXX ls $files_dir`;
    chomp($files);

    #say "$files";
    while ( $files =~ /nfcapd\.(\d+)/g ) {
        my $nf_file = $&;
        my $nf_date = $1;
        my $stm = q {SELECT count(1) as count FROM traf_table WHERE traf_date = to_date (?,'YYYYMMDDHH24MI')};
        my $res = $dbh->selectall_arrayref( $stm, { Slice => {} }, $nf_date );
        my $traf_count = $res->[0]->{count};

        if ( $traf_count == 0 ) {
            my $file_name = $files_dir . '/' . $nf_file;
            say "$file_name   " . `date`;
            `scp oracle\@XXXXXXX:$file_name $script_dir`;
            my $local_file_name = $script_dir . $nf_file;
            my $hash;
            my $flow_i = new Net::NfDump (
                InputFiles => [$local_file_name],
                Filter  => $FILTER_IN,
                Fields  => 'dstip, bps, bytes',
                Aggreg  => 1,
                OrderBy => 'bytes'
            );
            $flow_i->query();

            while ( my ( $dstip, $bps, $bytes ) = $flow_i->fetchrow_array() ) {
                $dstip = Net::NfDump::ip2txt($dstip);
                my $d_bps = sprintf( "%d", $bps );
                $hash->{$dstip}->{bps_in} += $d_bps;
                $hash->{$dstip}->{ip} = $dstip;
            }
            $flow_i->finish();

            #flow OUT
            my $flow_o = new Net::NfDump (
                InputFiles => [$local_file_name],
                Filter  => $FILTER_OUT,
                Fields  => 'srcip, bps, bytes',
                Aggreg  => 1,
                OrderBy => 'bytes'
            );
            $flow_o->query();

            while ( my ( $srcip, $bps, $bytes ) = $flow_o->fetchrow_array() ) {
                $srcip = Net::NfDump::ip2txt($srcip);
                my $d_bps = sprintf( "%d", $bps );
                $hash->{$srcip}->{bps_out} += $d_bps;
                $hash->{$srcip}->{ip} = $srcip;
            }
            $flow_o->finish();

            $stm = q{SELECT aep.school_id,
                            aep.ip,
                            aep.netmask
                     FROM all_equipment_ports aep};
            $res = $dbh->selectall_arrayref( $stm, { Slice => {} } );

            foreach my $el ( @{$res} ) {
                if (   $el->{ip} ne '8.8.8.8' && $el->{netmask} ne '255.255.255.255' ) {
                    my $cidr     = netmask2cidr( $el->{netmask} );
                    my $net      = qq'$el->{ip}/$cidr';
                    my $iterator = make_ip_iterator($net);
                    while ( my $ip = $iterator->() ) {
                        $ip =~ s/^(\d+\.\d+\.\d+\.\d+)\/\d+$/$1/;    #grep  mask
                        if ( $hash->{$ip} ) {
                            if (   $hash->{$ip}->{bps_in} || $hash->{$ip}->{bps_out} ) {
                                insert_val( $el->{school_id}, $nf_date, $hash->{$ip} );
                            }
                        }
                    }
                }
                else {
                    my $ip = $el->{ip};
                    if ( $hash->{$ip} ) {
                        if ( $hash->{$ip}->{bps_in} || $hash->{$ip}->{bps_out} ) {
                            insert_val( $el->{school_id}, $nf_date, $hash->{$ip} );
                        }
                    }
                }
            }
            $dbh->commit;
            `rm -rf $local_file_name`;
        }
    }
    $dbh->disconnect();
    my $elapsed = Time::HiRes::tv_interval( [$start], [Time::HiRes::gettimeofday] );
    say "execution time: $elapsed";
}else{
    $dbh->disconnect();
}

sub dec2bin {
    my $str = unpack( "B32", pack( "N", shift ) );
    return $str;
}
sub netmask2cidr {
    my ($mask) = @_;
    my @octet = split( /\./, $mask );
    my @bits;
    my $binmask;
    my $binoct;
    my $cidr = 0;

    foreach (@octet) {
        $binoct = dec2bin($_);
        $binmask = $binmask . substr $binoct, -8;
    }
    @bits = split( //, $binmask );
    foreach (@bits) {
        if ( $_ eq "1" ) {
            $cidr++;
        }
    }
    return $cidr;
}
sub make_ip_iterator {
    my $ip = shift;
    my $mask = NetAddr::IP->new($ip);
    my $iter = 0;
    return sub {
        return $mask->nth( $iter++ );
      }
}
sub insert_val {
    my ( $school_id, $nf_date, $hash ) = @_;
    my $stm = q{INSERT INTO
                  traf_table (
                          school_id,
                          ip,
                          traf_date,
                          download,
                          upload)
                VALUES ( ?, ?, to_date(?,'YYYYMMDDHH24MI'),nvl(?,0) ,nvl(?,0) )};
    my @bind = ( $school_id, $hash->{ip}, $nf_date, $hash->{bps_in}, $hash->{bps_out} );
    my $res = $dbh->do( $stm, { Slice => {} }, @bind );
    die unless $res;
}
