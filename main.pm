package main;


# v.2.2 mouse

use Class::Load ':all';

use Modern::Perl;
use HTTP::Date qw ();
#use Mail::Sendmail;
#use Net::DNS;
#use DBD::Pg;
#use DBD::mysql;
use File::Path qw(make_path);
use PAB3::Crypt::XOR qw(:default);
use Digest::MD5 qw(md5_hex md5);
#use DBI qw(:sql_types);
#use Cache::Memcached::Fast;

#####use MongoDB;
#####use DBD::SQLite;

#use IO::Socket::UNIX;
#use IO::Socket::INET;
#use IO::Socket::Timeout;
use Socket;
#use Socket qw(IPPROTO_TCP TCP_NODELAY);
use Socket qw(MSG_NOSIGNAL PF_INET PF_UNIX IPPROTO_TCP SOCK_STREAM TCP_NODELAY);
#use IO::Handle ();

#use IO::Socket::With::Timeout;

use Errno qw(ETIMEDOUT EWOULDBLOCK EINPROGRESS EISCONN);
use POSIX qw(ceil floor);
use List::MoreUtils qw{ any };
#use Crypt::Lite;
#use Crypt::Passwd::XS;
#use Crypt::RC4::XS;
#use Crypt::Blowfish;
#use List::MoreUtils qw(true);
#use MongoDB::OID;
use URI::Escape::XS qw(uri_escape uri_unescape);

use MIME::Base64::URLSafe;

use Time::HiRes qw(gettimeofday tv_interval);
use MIME::Base64 qw(encode_base64 decode_base64);
#use HTML::Entities;

use WWW::Curl::Easy;

#use Time::Seconds;

######use Text::Xslate;

#use Apache::Reload;
#use DateTime;
#use DateTime::Locale;
#use DateTime::Format::Strptime;
use String::Random qw(random_regex random_string);
#use IO::File;
use Data::Dumper;
use File::Slurp;
use Time::Local;
#use Net::DNS qw(mx);
use List::Util qw(shuffle);
use utf8;
use Encode qw(encode encode_utf8 decode_utf8);

use MIME::Lite;

#use main::www;
use lib qw(/home/adult/engine);

####use Redis::Client;

#use Crypt::RC4::XS;

use Moose;

has 'c' => ( is=>'rw', isa=>'main::config', required => 1 );
has 'res' => ( is => 'rw', isa => 'Plack::Response' );


sub uri_split {
	if (!defined($_[1])) { return (undef,undef,undef,undef,undef); }
	return $_[1] =~ m,(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?,;
}

sub crypt_str
{
	my $self = shift;
	my $str = shift;
	my $type = shift || 'xor';
#	my $crypt = new Crypt::Lite;

#	my $crypted = $crypt->encrypt($str,$self->c->dbdata->{md5_secret});
#	$crypted =~ s/[\r\n]+//g;
#	my $crypted = crypt($str,$self->c->dbdata->{md5_secret});
	my $md5_secret = $self->c->dbdata->{md5_secret};
	if ($self->c->in->{cj_hash}->{md5_secret}) {
		$md5_secret = $self->c->in->{cj_hash}->{md5_secret};
	}
	
	return $self->c->cval->{'SALT'} . xor_encrypt_hex( $md5_secret, $str ) if ($type eq 'xor');

	return encode_base64($str,"");

	#return encode_base64($self->c->crypt->encrypt($str));

	return uri_escape($self->c->crypt->encrypt($str,$self->c->dbdata->{md5_secret}));
#	return uri_escape($crypted);
}

sub decode_id
{
    my $self = shift;
    my $id = shift;
    my $crypt_mode = shift;
    my $md5_secret = shift;

#    print STDERR "start decoding id\n";

    if (!defined($md5_secret)) {
        $md5_secret = $self->c->dbdata->{md5_secret};
		if ($self->c->in->{cj_hash}->{md5_secret}) {
			$md5_secret = $self->c->in->{cj_hash}->{md5_secret};
		}
    }


    if (!defined($crypt_mode) && ref($self->c->in->{cj_hash})) {
        $crypt_mode = $self->c->in->{cj_hash}->{crypt_mode};
    } elsif (!defined($crypt_mode)) {
        $crypt_mode = 1;
    }

    my $salt = $self->c->cval->{'SALT'};

#	print STDERR "salt  $salt\n";

    if ($self->c->in->{a} eq 'get_cat' && ($crypt_mode eq 3 || $crypt_mode eq 4 || $crypt_mode eq 6)) {
#    	print STDERR "using cryotmode 3 4 6\n";

    	my $cat_add = $self->c->in->{cj_hash}->{cat_add} || '.html';
        $self->c->in->{cat_id} =~ s/\Q$cat_add\E$//;

       
        my $name = "name";
        if ($self->c->in->{lang} ne 'en') { $name .= "_" . $self->c->in->{lang}; }
        my $data = $self->mongo({db=>"cjs", table => "cats"})->find_one({$name => lc(decode_utf8($self->c->in->{cat_id})) }, {_id => 1});
        if (ref($data)) {
            return $data->{_id}
        } else {
            return 0;
        }

    }
#    if ($self->c->in->{a} eq 'go') { print STDERR "fetched go to decode $id\n"; }

#	print STDERR "decoding  $id\n";

    if ($id !~ /^\d+$/ || ($id =~ /^$salt/ || $id =~ /^a2/ || $id =~ /^7f/)) {
                if ($self->c->in->{a} eq 'go' || $crypt_mode eq 1 || $crypt_mode eq 3) {
#                	print STDERR "decoding go2 $id\n";
                   # if ($self->c->in->{a} eq 'go') { print STDERR "decoding go2 $id\n"; }
                    $id = decode_base64($id);
                    #if ($self->c->in->{a} eq 'go') { print STDERR "decoded go2 $id\n"; }
                } elsif ($crypt_mode eq 2 || $crypt_mode eq 4) {
                    $id = $self->decrypt_str($id,'xor',$md5_secret)
                }
                #my $cj_id = $self->c->in->{cj_hash}->{id};
                $id =~ s/^$salt\-//;
                $id =~ s/^a2\-//;
                $id =~ s/^7f\-//;
                $id =~ s/^\d+\-//;
#                if ($self->c->in->{a} eq 'go') { print STDERR "returning decoded go2 $id\n"; }
        return $id;
    } else {
        return $id;
    }    
}



sub decrypt_str
{
	my $self = shift;
	my $str = shift;
	my $type = shift || 'xor';
	my $md5_secret = shift || '';

#	print STDERR "str: " . $str . "\n";

#	my $crypt = new Crypt::Lite();
	my $salt = $self->c->cval->{'SALT'};

	if (!$md5_secret) {
		$md5_secret = $self->c->dbdata->{md5_secret};
		if ($self->c->in->{cj_hash}->{md5_secret}) {
			$md5_secret = $self->c->in->{cj_hash}->{md5_secret};
		}
	}	

#	print STDERR "dec: " . $crypt->decrypt(uri_unescape($str),$self->c->dbdata->{md5_secret}) . "\n";
	if ($type eq 'xor') {
		$str =~ s/^$salt//;
		$str =~ s/^a2//;
		$str =~ s/^7f//;
		return xor_decrypt_hex( $md5_secret, $str );
	}


	my $d = decode_base64(uri_unescape($str));
	$d =~ s/^\w+\-//;
	$d =~ s/^\w+\-//;
	return $d;

	return $self->c->crypt->decrypt(uri_unescape(decode_base64($str))) || die $!;

	#return $self->c->crypt->decrypt(uri_unescape($str));
	return $self->c->crypt->decrypt(uri_unescape($str),$self->c->dbdata->{md5_secret});
#	return $crypt->decrypt(uri_unescape($str),$self->c->dbdata->{md5_secret});
}

sub is_ref
{
	my $self = shift;
	my $val = shift;
	if (ref($val) eq 'SCALAR') {
		return ${$val};
	} elsif (ref($val) eq 'HASH') {
		return $val;
	} elsif (!ref($val)) {
		return $val;
	}

}


sub _init_ind_old
{
	my $self = shift;

	if (ref($self->c->ind_sock)) {
		$self->c->ind_sock->send("PING;");
		my $resp = undef;
		sysread $self->c->ind_sock, $resp, 5;
		#$self->logger("ping readed: '" . $resp . "'","new_system.log");
		if (defined($resp) && $resp eq "OK\n.\n") { $self->logger("Using OLD","new_system.log"); return 1; }
		if (!defined $resp && ( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK )) {
			$self->logger("\e[1;31m PING TIMEOUT: '" . $resp . "' \e[m","new_system.log");
			$self->logger("\e[1;31m PING TIMEOUT: '" . $resp . "' \e[m","new_system_timeout.log") if (( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK ));
		}
	}
	
	my $connect_str = (exists($self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{SOCKET})) ? 'unix://' . $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{SOCKET} : $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{HOST}  . ":" . $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{PORT};

	#$self->logger("Connecting...","new_system.log");
	#say STDERR $connect_str;

	if ($self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{SOCKET}) {
        $self->c->ind_sock(IO::Socket::UNIX->new( Peer => $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{SOCKET},
                                     Timeout => $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT},
#                                     ReadTimeout => $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT},
 #                                    WriteTimeout => $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT},
            ));
    }
    else {
        $self->c->ind_sock(IO::Socket::INET->new( PeerPort => $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{PORT},
                                     PeerAddr => $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{HOST},
                                     Proto => 'tcp',
                                     Timeout => $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT},
 #                                    ReadTimeout => $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT},
 #                                    WriteTimeout => $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT},                                     
         ));
    }
    if (!ref($self->c->ind_sock) || !$self->c->ind_sock->connected) {
    	$self->logger("no socket...","new_system.log");
    	$self->error("Cannot connect to IND socket: $!");
    	return undef;
    }
	setsockopt($self->c->ind_sock, IPPROTO_TCP, TCP_NODELAY, 1);

#	IO::Socket::Timeout->enable_timeouts_on($self->c->ind_sock);
 #   $self->c->ind_sock->read_timeout($self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT});
 #   $self->c->ind_sock->write_timeout($self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT});

    $self->logger("Connected: " . ref( $self->c->ind_sock ),"new_system.log");

    return 1;

}

sub ping_sock
{
		my $self = shift;

		send($self->c->ind_sock,"PING;",0);
		my $resp = undef;
		sysread $self->c->ind_sock, $resp, 5;
		#$self->logger("ping readed: '" . $resp . "'","new_system.log");
		if (defined($resp) && $resp eq "OK\n.\n") { $self->logger("Using OLD","new_system.log"); return 1; }
#		if (!defined $resp && ( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK )) {
#			$self->logger("\e[1;31m PING TIMEOUT: '" . $resp . "' \e[m","new_system.log");
#			$self->logger("\e[1;31m PING TIMEOUT: '" . $resp . "' \e[m","new_system_error.log") if (( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK ));
#		}
		return 0;
}

sub _init_ind
{
	my $self = shift;
	my $opt = shift || {};

	if (exists($ENV{IND_FORCE}) && $ENV{IND_FORCE}) {
		#say STDERR "setting ind force server: $server_id\n";
		$opt->{force} = 1;
	}

	if (!$opt->{force}) {
		if (!exists($self->c->cval->{IND_COUNT})) { $self->c->cval->{IND_COUNT} = 0; }
		$self->c->cval->{IND_COUNT}++;
		if ($self->c->cval->{IND_COUNT} > 10) { return undef; }
	}

	my $server_id = $self->c->dbdata->{current_server};
	if (exists($opt->{server_id}) && exists($self->c->dbdata->{servers}->{$opt->{server_id}})) { $server_id = $opt->{server_id}; }
	if ($self->c->current_db && exists($self->c->dbdata->{servers}->{$self->c->current_db})) { $server_id = $self->c->current_db; }

	if (!$opt->{force} && ref($self->c->ind_sock) && $self->c->ind_sock) {
		if ($self->ping_sock()) { return 1; }
	}
	

	my $proto = getprotobyname('tcp');
	my $sock;
	socket($sock, AF_INET, SOCK_STREAM, $proto) or  do {
			$self->logger("Cannot create socket: $!","new_system_error.log");
			return undef;
		};
	setsockopt($sock, IPPROTO_TCP, TCP_NODELAY, 1);
	#print STDERR "conn to: " . $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{HOST} . " "  . $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{PORT} . "\n";
	connect($sock , 
		pack_sockaddr_in($self->c->dbdata->{servers}->{$server_id}->{cfg}->{IND}->{PORT}, inet_aton($self->c->dbdata->{servers}->{$server_id}->{cfg}->{IND}->{HOST}))) 
		or do {
			$self->logger("Cannot connect socket: $!","new_system_error.log");
			return undef;
		};


    if (!ref($sock)) {
    	$self->logger("no socket...","new_system_error.log");
    	$self->error("Cannot connect to IND socket: $!");
    	return undef;
    }
	
	$self->c->ind_sock($sock);

#	IO::Socket::Timeout->enable_timeouts_on($self->c->ind_sock);
 #   $self->c->ind_sock->read_timeout($self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT});
 #   $self->c->ind_sock->write_timeout($self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT});

    $self->logger("Connected: " . ref( $self->c->ind_sock ),"new_system_error.log");

    if (!$self->ping_sock) { $self->logger("ReConnected","new_system_error.log"); $self->_init_ind(); }

    return 1;

}

sub isFloatsEqual
{
	my $self = shift;
	my ($a,$b) = @_;
	if (!defined($b)) { $b = 0; }

	if ($a == $b) {
        return 1;
    } elsif ($a eq $b) {
        return 1;
    }
    return sprintf("%.20f",$a) eq sprintf("%.20f",$b);
}

# sub write_ind
# {
# 	my $self = shift;
# 	my $cmd = shift;

# 	my $sock = $self->c->ind_sock;
# 	if (!$sock) { $self->_init_ind(); }

# 	local $SIG{'PIPE'} = "IGNORE";
# 	my $copy_state = -1;

# 	my $state = 0;
# 	my ($rin, $rout, $win, $wout);
# 	my $nfound;
#     my $res;
#     my ($ret, $offset) = (undef, 0);
# # the select loop
#     while(1) {

#         if ($copy_state!=$state) {
#             last if $state==2;
#             ($rin, $win) = ('', '');
#             vec($rin, fileno($sock), 1) = 1 if $state==1;
#             vec($win, fileno($sock), 1) = 1 if $state==0;
#             $copy_state = $state;
#         }
#         $nfound = select($rout=$rin, $wout=$win, undef,
#                          $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT});
#         last unless $nfound;

#         if (vec($wout, fileno($sock), 1)) {
#             $res = send($sock, $cmd, 0);
#             next
#                 if not defined $res and $!==EWOULDBLOCK;
#             unless ($res > 0) {
#                 close($sock);
#                 $self->logger("\e[1;31m Error reading: res: $res, cmd: $cmd\e[m","new_system_error.log");
#                 return undef;
#             }
#             if ($res == length($cmd)) { # all sent
#                 $state = 1;
#             } else { # we only succeeded in sending some of it
#                 substr($cmd, 0, $res, ''); # delete the part we sent
#             }
#         }

#         if (vec($rout, fileno($sock), 1)) {
#             $res = sysread($sock, $ret, 255, $offset);
#             next if !defined($res) and $!==EWOULDBLOCK;
#             if ($res == 0) { # catches 0=conn closed or undef=error
#                close($sock);
#                $self->logger("\e[1;31m Error reading: res: $res, cmd: $cmd\e[m","new_system_error.log");
#                return undef;
#             }
#             $offset += $res;
#             $self->logger("Readed res: $res, cmd: $cmd\e[m","new_system_error.log");
#             $state = 2 if ($ret eq "\n.\n");
#         }
#     }

#     unless ($state == 2) {
#         $self->logger("\e[1;31m Error reading: res: $res, cmd: $cmd\e[m","new_system_error.log");
#         return undef;
#     }

#     return $ret;



# }

sub _init_ind_new
{
	my $self = shift;


	my $sock = $self->c->ind_sock;

	if (ref($sock) && $sock) {

		my $resp = $self->write_ind("PING;");

		#$self->logger("ping readed: '" . $resp . "'","new_system.log");
		if (defined($resp) && $resp eq "OK\n.\n") { $self->logger("Using OLD","new_system.log"); return 1; }
		if (!defined $resp && ( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK )) {
			$self->logger("\e[1;31m PING TIMEOUT: '" . $resp . "' \e[m","new_system.log");
			$self->logger("\e[1;31m PING TIMEOUT: '" . $resp . "' \e[m","new_system_error.log") if (( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK ));
		}
		$self->logger("\e[1;31m NO PING RESPONSE, resp: '" . $resp . "' \e[m","new_system_error.log") 
	}
	

	$sock = undef;

    my $connected = 0;
    my $sin;
	my $proto = getprotobyname('tcp');
	
	
	socket($sock, AF_INET, SOCK_STREAM, $proto) or  do {
			$self->logger("Cannot create socket: $!","new_system_error.log");
			return undef;
		};
	$sin = Socket::sockaddr_in($self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{PORT}, Socket::inet_aton($self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{HOST}));

	#setsockopt($sock, IPPROTO_TCP, TCP_NODELAY, 1);
	IO::Handle::blocking($sock, 0) if ($self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT});
	my $ret = connect($sock, $sin);


	if (!$ret && $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT} && $!==EINPROGRESS) {

        my $win='';
        vec($win, fileno($sock), 1) = 1;

        if (select(undef, $win, undef, $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT}) > 0) {
            $ret = connect($sock, $sin);
            # EISCONN means connected & won't re-connect, so success
            $ret = 1 if !$ret && $!==EISCONN;
        }

#		$self->logger("Cannot connect socket timeout: $!","new_system_error.log");
#		return undef;
	};


   unless ($self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT}) { # socket was temporarily blocking, now revert
        IO::Handle::blocking($sock, 0);
    }

	my $old = select($sock);
    $| = 1;
    select($old);


    if (!ref($sock)) {
    	$self->logger("no socket...","new_system_error.log");
    	$self->error("Cannot connect to IND socket ret ($ret): $!");
    	return undef;
    }
	
	$self->c->ind_sock($sock);

#	IO::Socket::Timeout->enable_timeouts_on($self->c->ind_sock);
 #   $self->c->ind_sock->read_timeout($self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT});
 #   $self->c->ind_sock->write_timeout($self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{IND}->{TIMEOUT});

    $self->logger("Connected: " . ref( $self->c->ind_sock ) . ", ret: $ret","new_system.log");

    return 1;

}



sub email
{
	my $self = shift;
	my ($subject,$body,$sender,$to) = @_;

	$_ = encode('MIME-Header', $_) for $subject;
    utf8::encode( $body );
    
	$self->logger("$subject,$body,$sender,$to","email.log"); 

			my $msg = MIME::Lite->new(
        From     => qq{$sender},
        To       => qq{$to},
        Subject  =>$subject,
        Type    => 'multipart/related',
        
    );

$msg->attach(
        Type     => 'text/plain; charset=UTF-8',
        Data     => $body,
        Encoding => 'quoted-printable',
    );
        
    	$msg->send('sendmail', SetSender=>1);
    	
#    	$msg->send('smtp', $c->dbdata->{'SMTP'}->{'host'}, Debug => 1, Timeout=>30,
 #          AuthUser=>$c->dbdata->{'SMTP'}->{'login'}, AuthPass=>$c->dbdata->{'SMTP'}->{'passwd'});
 
 		$self->logger($msg->as_string,"email.log"); 
}

#sub e404
#{
#	my $self = shift;
#	my $data = shift;
#	$self->headers({ headers => { 
#		'Content-Type' => 'text/plain; charset=utf-8',
#		},
#		code => 404
#	});
#	$self->c->res->body('not found');
#	$self->c->res->finalize();
#	$self->exit_destr();
	#return 1;

#}


sub _choose_tx
{
	my $self  = shift;
	my $domain = shift;

	if (!$domain) {
		$domain = $self->c->env->{'HTTP_HOST'};
		$domain =~ s/:\d+$//g;
		$domain =~ s/www\.//g;
	}
	if (!$self->c->tx_hash->{$domain}) { $self->_init_tx(); }
#	print STDERR "tx hash dump: " . Dumper($self->c->tx_hash) . "\n";
#	print STDERR "dom:  $domain\n";



	$self->c->tx($self->c->tx_hash->{$domain});

}

sub _init_tx
{
	my $self = shift;
	my $templ_path_new = shift;

	#my $templ_path = $self->c->sysdata->{'TEMPLATE_DIR'} . $self->get_lang();
	
	
	#if ($self->c->cval->{'WEB'} eq 1 && ref($self->c->session) && ($self->c->session->{'ref_id'} eq 5031 || $self->c->cookies->{'devel'})) {
	#	$templ_path = $self->c->sysdata->{'TEMPLATE_DIR'} . 'dev';		
	#}
	load_class('Text::Xslate');
	
	#$self->logger("lang: " . $self->get_lang());

	#print STDERR Dumper($self->c->dbdata);

#	$self->_init_db() if (!$self->c->db);
		my $templ_path = "/home/adult/engine/templates";
		if (defined($templ_path_new)) { $templ_path = $templ_path_new; }
#		if (!-d "/home/adult/engine/tmp/xslate/" . $domain) { make_path("/home/adult/engine/tmp/xslate/" . $domain); }
		if (!-d "/home/adult/engine/tmp/xslate/all") { make_path("/home/adult/engine/tmp/xslate/all"); }
		$self->c->tx(Text::Xslate->new(
        syntax => 'TTerse',
        cache => 1,
        cache_dir => "/home/adult/engine/tmp/xslate/all",
        function => { 
        	fmt_size => sub { return $self->fmt_size(shift); }, in_array => sub { return $self->in_array(\$_[0],$_[1]); }, fmt_descr => sub { return $self->fmt_descr(shift,shift); }, fmt_name => sub { return $self->fmt_name(shift,shift,shift); }, fmt_spell => sub { return decode_utf8($self->fmt_spell(shift,shift)); }, 
        	get_cats_data => sub { return $self->get_cats_data(@_); },
        	get_ps_data => sub { return $self->get_ps_data(@_); },
        	get_toplist_data => sub { return $self->get_toplist_data(@_); },
        	get_tubes_data => sub { return $self->get_tubes_data(@_); },
        	#tag2cat => sub { return $adult->tag2cat(@_); },
        	rel2cat => sub { return $self->rel2cat(@_); },
        	#rel2search => sub { return $adult->rel2search(@_); },
        	add_slash => sub { if ($_[0] !~ /\/$/) { return $_[0] . "/"; } else { return $_[0]; } },
        	#get_cat_data => sub { return $adult->get_cat_data(@_); },
			get_gals => sub { return $self->get_gals_ind(@_); },
#			get_gals_sql => sub { return $adult->get_gals_sql(@_); },
        	#get_cat_thumb => sub { return $adult->get_cat_thumb(@_); },
        	#get_gal_thumb => sub { return $adult->get_gal_thumb(@_); },
        	tag2gal => sub { return $self->tag2gal_sql(@_); },
  #      	tag2obj => sub { return $adult->tag2obj(@_); },
        	
        	thumb2gal => sub { return $self->thumb2gal_sql(@_)},
     #   	thumb2gal_sql => sub { return $adult->thumb2gal_sql(@_)},
        	get_gal => sub { return $self->get_gal_data(@_)},
        	cat2gal => sub { return $self->cat2gal(@_)},
        	uri2 => sub { $_[0] =~ s/\s/-/g; $_[0] },
#        	thumb2cat => sub { return $adult->thumb2cat2(@_)},
        	
#        	set_vals => sub { return $adult->set_vals(@_); },
        	get_last_search => sub { return $self->get_last_search2(@_); },
        	e404 => sub { return $self->e404(@_); },

        	count_data => sub { return $self->img(@_); },

			#gal_by_tag => sub { return $adult->gal_by_tag(@_); },
			#gal_by_desc => sub { return $adult->gal_by_desc(@_); },
			#test => sub { return Dumper(Text::Xslate->current_vars()) },
        	e64 => sub { return encode_base64(shift,""); },
        	fmt_duration => sub { return $self->fmt_duration(@_); },
        	fmt_epoch => sub { return $self->fmt_epoch(@_); },
        	fmt_epoch_date => sub { return $self->fmt_epoch_date(@_); },
        	reorder => sub { return $self->reorder(@_); },
        	get_tags => sub { return $self->get_tags(@_); },
        	thumb_serv => sub { return $self->thumb_serv(@_); },
        	prepare_word  => sub { return $self->prepare_word(@_); },
        	trans  => sub { return $self->trans(@_); },
        	transm  => sub { return $self->transm(@_); },
        	trans_url => sub { return $self->trans_url(@_); },
        	in_array => sub { return $self->in_array(\$_[0],$_[1]); },
        	get_comments_data => sub { return $self->get_comments_data(@_); },
        	cat_by_lang => sub { return $self->cat_by_lang(@_); },
        	cutter => sub { return $self->cutter(@_); },
        	crypt_str => sub { return $self->crypt_str(@_); },
        	random => sub { return int(rand(shift)); },
        	ceil => sub { return ceil(shift) },
        	floor => sub { return floor(shift) },
        	encode_utf8 => sub { return encode_utf8(shift) },
        	decode_utf8 => sub { return decode_utf8(shift) },
        	rand_elem => sub { my $arr = shift; return $self->trans({ name => $arr->[rand @{$arr}] }); },
        	rand_str => sub { my @e = ('a'..'z','A'..'Z',0..9); return join '', @e[ map { rand @e } 1 .. shift ]; },
        	save_to_cache => sub { $self->save_to_cache(@_); },
        	get_from_cache => sub { return $self->get_from_cache(@_); },
#        	encode_entities =>  sub { return encode_entities(@_); },
        	#serv => sub { return int($_[0]/20); }
        	adv_show => sub { return $self->adv_show(@_); },
        	gal_info => sub { return $self->gal_info(@_); },
        	ucfirst => sub { if ($_[0]) { return ucfirst($_[0]); } else { return ''; } },
        	vid2gal => sub {
        				my $video_name = shift;
        				print STDERR "video name: $video_name\n" if ($self->c->env->{REMOTE_ADDR} eq '95.143.192.182');

                        my $video_expire = time() + 3600 * 24 * 30; # 30s
                        my $video_hash = urlsafe_b64encode(md5("secret123" . $video_name . $video_expire));
                        #$self->c->in->{g}->{video_url} = "/d/" . $video_hash . "/" . $self->c->in->{g}->{video_name} . "?e=" . $video_expire;
                        my $video_url = "/videos/" . $video_name . "?e=" . $video_expire . "&hash=" . $video_hash;

                        my $poster_expire = time() + 3600 * 24 * 30 * 12 * 100; # 30s

                        my $poster_name = $video_name;
                        $poster_name =~ s/\.\w+$/\.jpg/;

                        my $poster_hash = urlsafe_b64encode(md5("secret123" . $poster_name . $poster_expire));
                        #$self->c->in->{g}->{poster_url} = "/d/" . $poster_hash . "/" . $poster_url . "?e=" . $video_expire;
                        my $poster_url = "/videos/" . $poster_name . "?e=" . $poster_expire . "&hash=" . $poster_hash;

                        return { video_url => $video_url, poster_url => $poster_url };
        	},
        	add_suffix => sub {
        		if (exists($self->c->in->{cj_hash}->{cat_add}) && $self->c->in->{cj_hash}->{cat_add}) { return $self->c->in->{cj_hash}->{cat_add}; }
        		return '/';
        	},
        	add_suffix_cat => sub {
        		my $c = shift;
        		if ($self->in_array(\$self->c->in->{cj_hash}->{crypt_mode},[3,4,6])) { 
        			if (!exists($self->c->in->{cj_hash}->{cat_add})) { $self->c->in->{cj_hash}->{cat_add} = ''; }
        			return uri_escape($c->{name}) . $self->c->in->{cj_hash}->{cat_add};
        			
        		}
        		return $c->{encrypted3} . '/' . $c->{webname} . '/';
        	},
        	likes_prc => sub {
        		my ($likes,$dislikes) = @_;
        		#var likesPercents = Math.floor(likes * 100 / (likes + dislikes)) + '%';
        		if ($likes && $dislikes) {
        			return floor($likes * 100 / ($likes + $dislikes));
        		}
        		if (!$dislikes && $likes) { return 100; }
        		if ($dislikes && !$likes) { return 0; }
        		if (!$dislikes && !$likes) { return ceil(rand(30)) + 70; }

        	}
        },
        path => [$templ_path],
        warn_handler => sub {
        	#$self->mongo({db=>"cjs", table => "errors"})->update({},{ e => join(" ", @_)},{upsert => 1}); 
        	print STDERR "error: " . join(" ", @_) . "\n\n in: " . Dumper($self->c->env) . "\n"; 
        	#$self->logger("error: " . join(" ", @_) . "\n\n in: " . Dumper($self->c->env), "xslate.log");
        },
		module => [
            'Text::Xslate::Bridge::TT2Like'
        ],
    	)
    );
}

sub ind_cmd
{
	my $self = shift;
	my $cmd = shift;

	$self->_init_ind({force => 1});
	my $socket = $self->c->ind_sock;
	syswrite($socket,$cmd,length($cmd));
	my @resp = ();
	while(<$socket>) {
		my $line = $_;
		push @resp, $line;
		if ($line eq ".\n") { last; }
	}
	#close($socket);
	return \@resp;
}

sub cutter
{
	my $self = shift;
	my $hash = shift;



	if (!exists($hash->{name}) || !$hash->{name}) { return ''; }
	if (!exists($hash->{l}) || !$hash->{l}) { return $hash->{name}; }

	if (length($hash->{name}) <= $hash->{l}) { return $hash->{name}; }

	return substr($hash->{name},0,$hash->{l}) . $hash->{d};

}
sub fmt_epoch_date
{
	my $self = shift;
	my $data = shift;

	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =
                                                               localtime($data->{ts});

    $mon++;
    $year += 1900;



	return $mday . "." . $mon . "." . $year;                                                        
}

sub fmt_duration
{
	my $self = shift;
	my $duration = shift || 0;
	my $out;
	
	#if (!$duration) { print STDERR "d:" . $duration . "\n"; print STDERR "uri: " . $self->c->env->{HTTP_X_URI} . "\n"; $duration = 600; }
	use integer;

    my $secs  = $duration%60;
    my $tmins = $duration / 60;
    my $mins  = ($duration/60)%60;
    my $thrs  = $tmins / 60;
    my $hrs   = ($duration/(60*60))%24;
    my $days  = int($duration/(24*60*60));
	
	
	if ($mins < 10) { $mins = "0" . $mins; }
	if ($secs < 10) { $secs = "0" . $secs; }
	
	if ($days) { $hrs += int($days * 24); }	
	if ($hrs) { $out .= $hrs . ":"; }
	if ($mins) { $out .= $mins . ":"; }
	if ($secs) { $out .= $secs; }
	
	no integer;

	return $out;
	
}

sub cformat {
	my $self = shift;
	my $data = shift;
	
	if ($data->{'type'} eq 'email') {
	    if ($data->{'value'} !~ /^[A-Za-z0-9]+[\w\.\_\-]*[A-Za-z0-9\_\-]+\@[A-Za-z0-9]+[\w\.\-]*[A-Za-z0-9]*\.\w{2,10}$/) {
			return 0;
		}
	}

	if ($data->{'type'} eq 'email_mx') {

		$data->{'value'} =~ s/^.*\@//;
		my $res = new Net::DNS::Resolver;
		my @mx = mx($res, $data->{'value'});
		if (!@mx) {
			return 0;
		}    
	}
	
	if ($data->{'type'} eq 'length') {
		if ($data->{'min'} && length($data->{'value'}) < $data->{'min'}) { return 0; }
		if ($data->{'max'} && length($data->{'value'}) > $data->{'max'}) { return 0; }
	}
	
	if ($data->{'type'} eq 'between') {
		if ($data->{'value'} !~ /^\d+(\.\d+)?$/) { $data->{'value'} = 0; }

		if ($data->{'min'} && $data->{'value'} < $data->{'min'}) { return 0; }
		if ($data->{'max'} && $data->{'value'} > $data->{'max'}) { return 0; }
	}
	
	if ($data->{'type'} eq 'date') {
#		$self->logger("date check: " . $data->{'value'} . "-" . $self->date2epoch($data->{'value'}));
		return $self->date2epoch($data->{'value'});	
	}
	
	if ($data->{'type'} eq 'date_range') {
#		$self->logger("date range check: " . $data->{'min'} . "-" . $data->{'max'});
		if ($self->date2epoch($data->{'min'}) > $self->date2epoch($data->{'max'})) { return 0; }	
	}
	
	return 1;
}

sub date2epoch
{
	my $self = shift;
	my $ts = shift;
	
#	$self->logger("$ts");
	if (!defined($ts) || $ts !~ /^(\d{4})\-(\d{1,2})-(\d{1,2})$/) { 	
	#$self->logger("$ts bad regexp"); 
	return time; }
	elsif ($1 <= 999) { return time; }
	else {
		my $epoch = eval { 	timelocal(0,0,0,$3,$2-1,$1); };
		if ($@ || $epoch <= 0) { 
		#$self->logger("$ts bad epoch $@"); 
			return time;
		}
		return $epoch;
	}
}

sub epoch2date {
	my $self = shift;
	my ($epoch,$offset) = @_;

	$offset //= 0;


    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($epoch + $offset);
    $mon++;
    $year += 1900;

    if ($mon < 10) { $mon = "0" . $mon; }
    if ($mday < 10) { $mday = "0" . $mday; };

    if ($sec < 10) { $sec = "0" . $sec; }
    if ($hour < 10) { $hour = "0" . $hour; };
    if ($min < 10) { $min = "0" . $min; };
    
    return $year . "-" . $mon . "-" . $mday;
}

sub _init_mongo
{
	my $self = shift;
	my $options = shift || {};
	if (!exists($options->{w})) { $options->{w} = 1; }
	if (!exists($options->{r})) { $options->{r} = 0; }
	if (!exists($options->{server_id})) { $options->{server_id} = $self->c->dbdata->{current_server}; }
	if ($self->c->current_db) { $options->{server_id} = $self->c->current_db; }


	load_class('MongoDB');

	$MongoDB::Cursor::timeout = 6000000;
	
	my $dsn;
	if (exists($self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO'}->{'DSN'})) {
		$dsn = $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO'}->{'DSN'};
	} else {
		$dsn = "mongodb://" . $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO'}->{'HOST'} . ":" . $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO'}->{'PORT'};
	}

	my %conn_hash = (
#		host => $dsn, slaveok=> 1, connect_timeout_ms=> 60000, socket_timeout_ms => 60000, dt_type => undef, w => $options->{w}, inflate_dbrefs => 0
		host => $dsn, slaveok=> 1, dt_type => undef, connect_timeout_ms=> 6000000, socket_timeout_ms => 6000000, query_timeout => 6000000, timeout => 6000000, w => $options->{w}, inflate_dbrefs => 0
	);

	if (exists($self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO'}->{'USER'})) {
		$conn_hash{username} = $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO'}->{'USER'};
		$conn_hash{password} = $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO'}->{'PASSWORD'};
		$conn_hash{db_name} = $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO'}->{'DB'};
	}
	

	if (exists($self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO'}->{'REPLICA'})) {
		#$conn_hash{find_master} = 1;
	}

	$self->c->mongo_conn_pool->{$options->{server_id}} = MongoDB::MongoClient->new(%conn_hash);
	if (exists($self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO'}->{'REPLICA'})) {
		$self->c->mongo_conn_pool->{$options->{server_id}}->read_preference(MongoDB::MongoClient->SECONDARY_PREFERRED);
	}

	return;
	if ($options->{r} && ref( $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO_READ'} )) {
		my $dsn = $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO_READ'}->{'HOST'} . ":" . $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO_READ'}->{'PORT'};
    	$self->c->mongo_read_conn_pool->{$options->{server_id}} = (MongoDB::MongoClient->new(host => $dsn, slaveok=> 1, query_timeout => 6000000, timeout => 6000000, w => $options->{w}, dt_type => undef, inflate_dbrefs => 0, auto_reconnect => 1));
	} else {
		my $dsn = "mongodb://" . $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO'}->{'HOST'} . ":" . $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO'}->{'PORT'};
		if (ref( $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO_READ'})) {
			$dsn .= "," . $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO_READ'}->{'HOST'} . ":" . $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO_READ'}->{'PORT'};
		}
    	$self->c->mongo_conn_pool->{$options->{server_id}} = (MongoDB::MongoClient->new(host => $dsn, slaveok=> 1, query_timeout => 6000000, timeout => 6000000, w => $options->{w}, dt_type => undef, inflate_dbrefs => 0, auto_reconnect => 1));
#    	$self->c->mongo_conn_pool->{$options->{server_id}}->dt_type( undef );
    	if (ref( $self->c->dbdata->{servers}->{$options->{server_id}}->{cfg}->{'MONGO_READ'})) {
    		$MongoDB::Cursor::slave_okay = 1;
    		$self->c->mongo_conn_pool->{$options->{server_id}}->find_master(1);
    		$self->c->mongo_conn_pool->{$options->{server_id}}->read_preference(MongoDB::MongoClient->SECONDARY_PREFERRED);
    	}
    }
}

sub mongo
{
      my $self = shift;
      my $data = shift || {};
      $data->{db} =  $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{'MONGO'}->{'DB'} if (!$data->{db});
      $data->{server_id} =  $self->c->dbdata->{current_server} if (!$data->{server_id});
      if ($self->c->current_db) { $data->{server_id} = $self->c->current_db; }
      if (!exists($data->{r})) { $data->{r} = 0; } else { $data->{r} = 1; }
#      my $db = shift || $self->c->dbdata->{'MONGO'}->{'DB'};
      if (!$self->c->mongo_conn_pool->{$data->{server_id}}) { $self->_init_mongo({server_id => $data->{server_id}}); }
      if ($data->{r} && !$self->c->mongo_read_conn_pool->{$data->{server_id}} && ref($self->c->dbdata->{servers}->{$data->{server_id}}->{cfg}->{'MONGO_READ'})) { $self->_init_mongo({server_id => $data->{server_id}, r => 1}); }

      my $conn = $self->c->mongo_conn_pool->{$data->{server_id}};
      if ($data->{r} && ref($self->c->dbdata->{servers}->{$data->{server_id}}->{cfg}->{'MONGO_READ'})) {
      	$conn = $self->c->mongo_read_conn_pool->{$data->{server_id}};
      }

      if (exists($data->{root})) {
      	return $conn;
      }

      ($data->{table}) ? ($conn->get_database($data->{db})->get_collection( $data->{table} )) : ($conn->get_database($data->{db}));           

}


sub _init_dbl
{
	my $self = shift;
	my $options = shift || {};
	if (!exists($options->{db})) { $options->{db} = $self->c->cval->{CJ_ID}; }

	load_class('DBD::SQLite');
	
	$self->c->stmt_pool({});

	$self->c->dbl_pool->{$options->{db} . "_" . $$} = DBI->connect("dbi:SQLite" . ":dbname=/home/db/sqlite/" . $options->{db}, 
				undef, undef,
			{
			    sqlite_see_if_its_a_number => 1,
 				sqlite_use_immediate_transaction => 1,
				#mysql_init_command      => q{SET NAMES 'utf8';SET CHARACTER SET 'utf8'},
				AutoCommit => 1,  # Turn off autocommit to allow rollback.
				PrintError => 0,  # I create my own error messages using $handle->errstr
				RaiseError => 0   # I use die within eval to raise exceptions.
			}	
		) || die $DBI::errstr;

		if ($self->c->cval->{WEB}) {
			$self->c->dbl_pool->{$options->{db} . "_" . $$}->do("PRAGMA synchronous=OFF");
			$self->c->dbl_pool->{$options->{db} . "_" . $$}->do("PRAGMA read_uncommitted=1");
#		 	$self->c->dbl_pool->{$options->{db} . "_" . $$}->do("PRAGMA cache_size = 20000");
#		 	$self->c->dbl_pool->{$options->{db} . "_" . $$}->do("PRAGMA wal_autocheckpoint = 10000");
			
			#$self->c->dbl_pool->{$options->{db} . "_" . $$}->{CachedKids} = $self->c->sysdata->{PREPARED};		

		}

}

sub dbl
{
      my $self = shift;
      my $data = shift || {};
      $data->{db} =  $self->c->cval->{CJ_ID} if (!$data->{db});

      #if ($self->c->cval->{SYSTEM}) { say STDERR Dumper($data); }
      
      if (!$self->c->dbl_pool->{$data->{db} . "_" . $$} || !$self->c->dbl_pool->{$data->{db} . "_" . $$}->ping) {  $self->_init_dbl({db => $data->{db}}); }

      return $self->c->dbl_pool->{$data->{db} . "_" . $$};
}

sub _init_redis
{
	my $self = shift;
	my $options = shift || {};
	my $server_id = $self->c->dbdata->{current_server};
	if (exists($options->{server_id}) && exists($self->c->dbdata->{servers}->{$options->{server_id}})) { $server_id = $options->{server_id}; }
	if ($self->c->current_db && exists($self->c->dbdata->{servers}->{$self->c->current_db})) { $server_id = $self->c->current_db; }


	#load_class('Redis');
	load_class('Redis::Client');
	if ($self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_CLUSTER'}) {
		load_class('Redis::Cluster');
	}


	#$self->c->redis(Redis->new( server => $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS'}->[0] . ":" . $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS'}->[1], cnx_timeout => 5, read_timeout => 5, write_timeout => 5 ));
	$self->c->redis(Redis::Client->new( host => $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS'}->[0], port => $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS'}->[1] )) || print STDERR $@ . "\n";
	
	if (exists($self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_READ'})) {
		$self->c->sysdata->{'REDIS_READ'} = 0;

		#$self->c->redis_r(Redis->new( server => $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_READ'}->[0] . ":" . $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_READ'}->[1], cnx_timeout => 5, read_timeout => 5, write_timeout => 5 ));
		print STDERR "$$ connect to read " .  $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_READ'}->[0] . " " . $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_READ'}->[1] . "\n";

		$self->c->redis_r(Redis::Client->new( host => $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_READ'}->[0], port => $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_READ'}->[1], timeout => 2 ));
		print STDERR "$$ connected to read\n";
		my $redis_ping_result = undef;
		eval {
			$self->c->redis_r->set("connection",1);
			$redis_ping_result = $self->c->redis_r->get("connection");	
		};
		print STDERR "$$ main.pm ping res: '$@' '$redis_ping_result'\n";
		if ($@ || !$redis_ping_result) {
			print STDERR "ERROR redis read: $$ main.pm ping res: '$@' '$redis_ping_result'\n";
			$self->c->redis_r($self->c->redis);
		} else {
			print STDERR "setting redis read to 1\n";
			$self->c->sysdata->{'REDIS_READ'} = 1;
		}

	} elsif (exists($self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_CLUSTER'})) {
		$self->c->redis_r(Redis::Cluster->new( server => $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_CLUSTER'}));
		my $redis_ping_result = undef;
		eval {
			$redis_ping_result = $self->c->redis_r->ping;	
		};
		if ($@ || !$redis_ping_result) {
			$self->c->redis_r($self->c->redis);
		} else {
			$self->c->sysdata->{'REDIS_READ'} = 1;
		}
	} else {
		$self->c->redis_r($self->c->redis);
	}

}

sub _init_redis_old
{
	my $self = shift;
	my $options = shift || {};
	my $server_id = $self->c->dbdata->{current_server};
	if (exists($options->{server_id}) && exists($self->c->dbdata->{servers}->{$options->{server_id}})) { $server_id = $options->{server_id}; }


	load_class('Redis::Client');

	if (!exists($options->{readonly})) {
	
		if ($self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS'}->[2]) {
			$self->c->redis(Redis::Client->new( path => $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS'}->[2]));
		} else {
			$self->c->redis(Redis::Client->new( host => $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS'}->[0], port => $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS'}->[1] ));
		}
	}

	#$self->c->redis_r($self->c->redis);
	#return;
	
	if (exists($self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_READ'})) {
		print STDERR "init redis read\n";
		if ($self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_READ'}->[2]) {
			$self->c->redis_r(Redis::Client->new( path => $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_READ'}->[2] ));
		} else {
			print STDERR "init redis read with TCP\n";
			$self->c->redis_r(Redis::Client->new( host => $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_READ'}->[0], port => $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_READ'}->[1] ));
		}
		print STDERR $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_READ'}->[0] . " " . $self->c->dbdata->{servers}->{$server_id}->{cfg}->{'REDIS_READ'}->[1] . "\n";
		my $redis_ping_result = undef;
		eval {
			$redis_ping_result = $self->c->redis_r->echo("ping");	
		};
		print STDERR "init redis read ping: $redis_ping_result $@\n";
		if ($@ || !$redis_ping_result) {
			$self->c->redis_r($self->c->redis);
		} else {
			$self->c->cval->{'REDIS_READ'} = 1;
		}

	} else {
		$self->c->redis_r($self->c->redis);
	}
}

sub _init_memd
{
	my $self = shift;
	
	$self->c->memd(new Cache::Memcached::Fast { servers => $self->c->dbdata->{servers}->{$self->c->dbdata->{servers}->{current_server}}->{cfg}->{'MEMCACHED'}, utf8 => 1, compress_threshold => 921600});
}
sub rand_from_array
{
	my $self = shift;
	my $arr = shift;
	my $count = shift;
	$count--;
	
	my @arr_tmp = shuffle(@{$arr});
	my @arr_toreturn = ();
	foreach (0..$count-1) {
		if ($arr_tmp[$_]) { push @arr_toreturn, $arr_tmp[$_]; }
	}
	
	return \@arr_toreturn;
	
}
sub rem_from_array
{
	my $self = shift;
	my $arr = shift;
	my $torem = shift;
	
	my @array = @{$arr};
	
	if (ref($arr) ne 'ARRAY') { return (); }
	
	for ( my $index = $#array; $index >= 0; --$index )
	{
		#print STDERR "REM FROM: '$array[$index]' - '$torem'\n";
	  splice @array, $index, 1
	    if (($array[$index] eq $torem) || (ref($array[$index]) eq 'SCALAR' && ${$array[$index]} eq $torem));
	}
	
	return @array;
}

sub fmt_spell
{
	my $self = shift;
	my $val = shift;
	my $type = shift;
	
	if (!$self->c->miscdata->{'SPELL'}->{$self->c->in->{'lang_id'}}) { return $val; }
	
#	if ($self->c->in->{'lang_id'} ne 2) { return $val; }
    
    $val = abs($val) % 100;
    my $val1 = $val % 10;
    if ($val > 10 && $val < 20) { return decode_utf8($self->c->miscdata->{'SPELL'}->{$self->c->in->{'lang_id'}}->{$type}->[2]); }
    if ($val1 > 1 && $val1 < 5) { return decode_utf8($self->c->miscdata->{'SPELL'}->{$self->c->in->{'lang_id'}}->{$type}->[1]); }
    if ($val1 == 1) { return decode_utf8($self->c->miscdata->{'SPELL'}->{$self->c->in->{'lang_id'}}->{$type}->[0]); }

    return decode_utf8($self->c->miscdata->{'SPELL'}->{$self->c->in->{'lang_id'}}->{$type}->[2]);
}

sub detect_lang
{
	my $self = shift;

		
}

sub add_email
{
	my $self = shift;
	my ($sender_name,$sender_email,$recv_name,$recv_email,$subj,$body) = @_;
	
	my $sql = new SQL::Abstract;


		
		my $id = $self->next_seq_id('mail_queue');
		my $data = {
				id => $id,
				sender_name => $sender_name,
				sender_email => $sender_email,
				recv_name => $recv_name,
				recv_email => $recv_email,
				subject => $subj,
				body => $body,
			};
			
		my($stmt, @bind) = $sql->insert('mail_queue', $data);
#		$self->logger($stmt . " - " . join(" " , @bind));
		my $res = $self->c->db->prepare($stmt);
		$res->execute(@bind) || $self->error("SQL: $stmt " . join(" " , @bind) . " " . $res->errstr);;
		$res->finish;
		
		return $id;	
}

sub fmt_descr
{
	my $self = shift;
	my $name = shift;
	my $limit = shift || 70;
	
	if ( utf8::is_utf8($name)) { $limit = 55; }
	#$self->logger("fmt_name: $name $start $end");
	my $out = undef;
		
	if (length($name) > $limit) {
		$name =~ s/([^\n]{$limit})/$1\n/g;
		return $name;
#		$name =~ s/^[\s\t]*//;
#		my $chunk = '';
#		foreach my $w (split(/\s+/, $name)) {
#			$w =~ s/([^\n]{5})/$1\n/g;
#			$chunk .= $w . " ";
#			if (length($chunk) > $limit) { $out .= $chunk . "\n"; $chunk = ''; } else { $out .= $chunk; }
#		}
	}
	return $name;
}

sub fmt_name
{
	my $self = shift;
	my $name = shift;
	my $start = shift || 50;
	my $end = shift || 10;
	
	if ( utf8::is_utf8($name)) { $start = 35; }
	
	#$self->logger("fmt_name: $name $start $end");
	
	if (length($name) > 70) {
		$name =~ s/^(.{$start}).*(.{$end})/$1\.\.\.\.\.\.\.$2/;
	}
	return $name;
}

sub fmt_size
{
	my $self = shift;
	my $_size = shift;
	my $return = undef;
	if ($_size < 1024) { $return = sprintf("%d %s", $_size , $self->c->miscdata->{'SIZE'}->{$self->get_lang()}->{1}); }
	elsif (($_size / 1024) >= 1 && ($_size / 1024) < 1024) { $return = sprintf("%.2f %s", ($_size / 1024) , $self->c->miscdata->{'SIZE'}->{$self->get_lang()}->{2}); }
	elsif (($_size / 1024 / 1024) >= 1 && ($_size / 1024 / 1024) < 1024) { $return = sprintf("%.2f %s", ($_size / 1024 / 1024), $self->c->miscdata->{'SIZE'}->{$self->get_lang()}->{3}); }
	elsif (($_size / 1024 / 1024 / 1024) >= 1) { $return = sprintf("%.2f %s", ($_size / 1024 / 1024 / 1024), $self->c->miscdata->{'SIZE'}->{$self->get_lang()}->{4}); }

	return decode_utf8($return);
}

sub format_hash
{
	my $self = shift;
	my $hash = shift;
	my $opts  = shift;
	
	foreach (keys %{$hash}) {
		#$self->logger($_ . " - " . $hash->{$_});
		if ($_ =~ /^ts/ && $hash->{$_} && $_ ne 'tsv' && $hash->{$_} =~ /^\d+\-\d+\-\d+ \d+:\d+:\d+/) {
			$hash->{$_} = $self->parse_timestamp($hash->{$_},$self->get_lang(), $opts->{'format'});
		}
		if ($self->in_array(\$_,['total_size_in_account_kb','max_size_per_file_kb','min_payed_size_kb','ftp_max_file_size_kb'])) {
			$hash->{$_} = sprintf("%d", $hash->{$_});
		}
	}	
}


sub parse_timestamp
{
	my $self = shift;
	my ($ts,$locale,$format) = @_;
	$ts =~ s/\..*$//;
	
	my $loc =  DateTime::Locale->load($locale);
	my $strp = DateTime::Format::Strptime->new(
		pattern   => '%F %T',
		locale    => $locale,
	);
	my $dt = $strp->parse_datetime($ts);
	
	#$self->logger("Formats: " . Dumper($loc->available_formats()));
	#$self->logger($ts . " - " . $dt . " - " . $locale);

#	use Time::Format qw(%time %strftime %manip);
	

 #	return $time{'Month d, yyyy',$dt};
 	
#	return $dt->format_cldr($loc->format_for('yMMMEd'));
#	return $dt->format_cldr('yMMMEd HHmm');
	
	if ($format eq 'long') {
#		return $dt->format_cldr($loc->date_format_medium) . " " . $dt->format_cldr($loc->time_format_short);
		return $dt->format_cldr($loc->format_for('yMMMEd')) . " " . $dt->format_cldr($loc->format_for('hm'));
	}
#	return $dt->format_cldr($loc->format_for('yMMMEd')) . " " . $dt->format_cldr($loc->format_for('HHmm'));
#	return return $dt->format_cldr($loc->date_format_medium);
	return $dt->format_cldr($loc->format_for('yMMMEd'));
#	return $dt->format_cldr($loc->datetime_format_medium());
#	return $dt->format_cldr($loc->format_for('YYYYY MMMdd'));
}

sub timestamp2epoch {
	my $self = shift;
	my ($ts) = @_;

	if ($ts =~ /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/) {
		#print STDERR "dates: $6,$5,$4,$3,$2,$1\n";
		return timelocal($6,$5,$4,$3,$2-1,$1); 
	} else {
		return 0;
	}
}

sub epoch2timestamp {
	my $self = shift;
	my ($epoch,$offset) = @_;
	if (!$epoch) { $epoch = time; }
	if (!$offset) { $offset = 0; }


    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($epoch + $offset);
    $mon++;
    $year += 1900;

    if ($mon < 10) { $mon = "0" . $mon; }
    if ($mday < 10) { $mday = "0" . $mday; };

    if ($sec < 10) { $sec = "0" . $sec; }
    if ($hour < 10) { $hour = "0" . $hour; };
    if ($min < 10) { $min = "0" . $min; };
    
    return $year . "-" . $mon . "-" . $mday . " " . $hour . ":" . $min . ":" . $sec;
}

sub hash_replace (\%$$) {
	my $self = shift;
	$_[0]->{$_[2]} = delete $_[0]->{$_[1]}; # thanks mobrule!
}

sub in_array_old
{
	my $self = shift;
	my ($value,$array) = @_;
	if (ref($value) ne 'SCALAR' || ref($array) ne 'ARRAY') { return(0); }
	{ 
		no warnings;
		foreach my $val (@{$array}) {
			if ($val eq ${$value}) { return(1); }
		}
	}
	return (0);
}

sub in_array
{
	my $self = shift;
	my ($value,$array) = @_;
	if (ref($value) ne 'SCALAR' || ref($array) ne 'ARRAY' || !defined(${$value}) || !scalar @{$array} ) { return(0); }

	if (any { defined($_) && $_ eq ${$value} } @{$array} ) {
		return 1
	}

	return 0;
}


sub parse_headers {
	my $self = shift;
	my $header = shift;

	my %headers = ();
	foreach my $line (split(/\r\n/, $header)) {
		if ($line =~ /^([\w-]+?):\s*(.*)/) {
			$headers{$1} = $2;
		}
	}
	return \%headers;
}

sub headers {
	my $self = shift;
	my $type = shift;
	if (!$self->c->res) { return; }
	
	my $out = undef;
	if (ref($type) ne 'HASH') {
		my $headers = {};
		if (!$self->{'header_type'}) {
			
			$headers = {
				#'Expires' => 'Sun, 1 Jan 2000 12:00:00 GMT',
				'Date' => HTTP::Date::time2str(time),
#				'Cache-Control' => 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0',
#				'Pragma' => 'no-cache',
#				'X-Robots-Tag' => 'notranslate',
				'Content-Language' => $self->c->in->{lang},
				'Content-Type' => 'text/html; charset=utf-8',
				#'X-SID' => $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{name}
#				'Access-Control-Allow-Origin' => '*',
				
			};
			if ($self->c->in->{'cj_hash'}->{'multilang'}) {
				$headers->{'X-Robots-Tag'} = 'notranslate';
#				$headers->{'Content-Language'} = $self->c->in->{lang};
			}
#			if ($self->c->env->{HTTP_X_SECURE} eq 'on') {
#				$headers->{'Strict-Transport-Security'} = 'max-age=10886400; includeSubDomains; preload';
#			}
			$self->c->res->headers($headers);
			$self->c->res->status(200);		
		} else {
			$out .= $self->{'header_type'} . "\r\n\r\n";
		}
	} else {
		$self->c->res->headers($type->{'headers'});
		$self->c->res->status($type->{'code'});
	}
}

sub error {
	my $self = shift;
	my ($error,undef,undef,$debug) = @_;
	if ($self->c->cval->{'WEB'}) {
		$self->c->res->headers({'Content-Type' => 'text/html; charset=utf-8'});
		$self->c->res->status(500);
	}	
	#print STDERR "ERROR:" . $error . "\n";
	#$self->logger("error fetched: $error");

	my $MSG = qq|

Error while processing some directives


Server time: |; $MSG .= scalar localtime; $MSG .= qq|

--
User generated error:
$error
--
ENV vars:
|;
#foreach my $key (keys %{$self->c->env}) {
#	$MSG .= "$key - " . $self->c->env->{$key} . "\n";
#}


if (ref($self->c->in) eq 'HASH' || ref($self->c->in) eq 'Hash::MultiValue') {
	$MSG .= qq|
	--
	IN vars:
	|;
	$MSG .= Dumper($self->c->in);
}

if (ref($self->c->cookies) eq 'HASH' || ref($self->c->cookies) eq 'Hash::MultiValue') {
	$MSG .= qq|
	--
	COOKIES:
	|;
	foreach my $key (keys %{$self->c->cookies}) {
		$MSG .= "$key - " . $self->c->cookies->{$key} . "\n";
	}
}

if (ref($self->c->session) ) {
	$MSG .= qq|
	--
	SESSION:
	|;
	
	$MSG .= Dumper($self->c->session->dump) . "\n";
}


$MSG .= qq|
|;

	$self->email(
					'Software error',
					$MSG,
					$self->c->sysdata->{'HOSTMASTER'}->[0],$self->c->sysdata->{'HOSTMASTER'}->[1],
					$self->c->sysdata->{'HOSTMASTER'}->[0],$self->c->sysdata->{'HOSTMASTER'}->[1]
				);

	$self->logger("error fetched: $error $MSG");

	if ($self->c->cval->{'WEB'}) {
		if ($self->c->sysdata->{'DEBUG'} || $self->c->in->{debug}) {
		#	$self->logger("setting error body");
			$MSG =~ s/\n/<BR>\n/g;
			if ($self->c->res) {
				$self->c->res->body($MSG);
				#$self->c->res->finalize();
			}
		#	exit;
		} else {
			$MSG =~ s/\n/<BR>\n/g;
			$self->c->res->body(500);
			#print $MSG if ($debug);
	#		print qq|
	#	500 software error
	#
	#		|;
		}
	}
	if ($self->c->cval->{SYSTEM}) {
		print $MSG;
	}

	#$self->logger("Error: " . $MSG);

}

sub _init_db {
	my $self = shift;
#	my $server_id = shift || $self->c->dbdata->{current_server};
		$self->c->stmt_pool({});

		$self->c->db(DBI->connect("dbi:" . $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{'DB'}->{'DRV'} . ":dbname=" . $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{'DB'}->{'NAME'} . ";port=" . $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{'DB'}->{'PORT'} . ";host=" . $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{'DB'}->{'HOST'}, 
				$self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{'DB'}->{'USER'}, $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{'DB'}->{'PASSWD'},
			{
				pg_auto_escape => 1,
				pg_enable_utf8 => 1,
				pg_expand_array => 1,
				pg_errorlevel => 2,
				ShowErrorStatement => 1,
#				HandleError => sub { $self->error(shift); },
				mysql_enable_utf8 => 1,
				mysql_auto_reconnect => 1,
				mysql_unsafe_bind_type_guessing => 2,
				#mysql_init_command      => q{SET NAMES 'utf8';SET CHARACTER SET 'utf8'},
				AutoCommit => 1,  # Turn off autocommit to allow rollback.
				PrintError => 0,  # I create my own error messages using $handle->errstr
				RaiseError => 0   # I use die within eval to raise exceptions.
			}	
		)) || die $DBI::errstr;

		$self->mysql_cmd("SET CLIENT_ENCODING TO 'UTF8'");
#		$self->{db}->{mysql_auto_reconnect} = 1;
}

sub send_mail {
	my $self = shift;
	my ($toaddr, $subj, $msg, $from,$hash) = @_;
	if (!$from || $from =~ /^\n/)	{	$from = $self->c->sysdata->{'HOSTMASTER'};	}
	

	$Mail::Sendmail::mailcfg{smtp}->[0] = $self->c->dbdata->{servers}->{$self->c->dbdata->{current_server}}->{cfg}->{'SMTP'};
	$Mail::Sendmail::mailcfg{from} = $from;
	$Mail::Sendmail::mailcfg{retries} = 3;
	$Mail::Sendmail::mailcfg{delay} = 20;


	my %mail = ( 'Content-Type' => 'text/plain;',
					To      => $toaddr,
                 From    => $from,
					Subject => $subj,
                   Message => $msg
                  );

	if (ref($hash) eq 'HASH') {
		foreach (keys %{$hash}) {
			$mail{$_} = $hash->{$_};
		}
	}

	sendmail(%mail);
	if ($Mail::Sendmail::error) {
#		$self->logger("MAIL ERROR: " . $Mail::Sendmail::error);

		return $Mail::Sendmail::error;
	}
	return "ok";
}

sub parse_cookies_header
{
	my $self = shift;
	my $header = shift;

	my %cookies = ();
	foreach my $line (split(/\n/, $header)) {
		if ($line =~ /^Set-Cookie:\s*(\w+)=(.*?);/) {
			$cookies{$1} = $2;
		}
	}
	return \%cookies;
}

sub stimer 
{
	my ($self,$name) = @_;
	$self->c->cval->{TIMES}->{$name} = [scalar times,[gettimeofday]];
}

sub etimer 
{
	my ($self,$name,$log) = @_;
	if (!defined($log)) { $log = ''; }
	if (!exists($self->c->cval->{TIMES}->{$name})) {
		$self->logger($name . " - NOT START DATA","cpu.log");
		return;
	}
#	my @differences = map { $end_time[$_] - $self->c->cval->{TIMES}->{$name}->[$_] }
#				(0..3);

#	my $difference = join ', ', @differences;
	$self->logger($name . " - " . $log . " bench: " . (scalar times - $self->c->cval->{TIMES}->{$name}->[0]) . ", time: " . tv_interval($self->c->cval->{TIMES}->{$name}->[1]),"cpu.log");
	delete $self->c->cval->{TIMES}->{$name};

}



sub logger
{
	my $self = shift;
	no warnings;
#	print STDERR "return from logger " . $self->c->dbdata->{'debug'} . "\n";
	my $local_debug = $self->c->dbdata->{'debug'};
	{
		no warnings;
		if ($self->c->env->{REMOTE_ADDR} eq '109.206.188.250' || $self->c->env->{REMOTE_ADDR} eq '95.143.192.182' || $self->c->env->{REMOTE_ADDR} eq '216.172.63.50' || $self->c->env->{REMOTE_ADDR} eq '91.236.116.18') { $local_debug = 1; }
		#if ($self->c->cval->{CJ_ID} eq 47) { $local_debug = 1; }
	}
	#if ($self->c->cval->{CJ_ID} eq 53) { $local_debug = 1; }
	#if ($self->c->cval->{CJ_ID} eq 80) { $local_debug = 1; }
	if (!$local_debug) { return 0; }
#	return 1;
#	print STDERR "in logger\n";
#	return;

#	my ( $package, $filename, $line ) = caller;

#	print  STDERR $package . " => " . $self->TTT() . "\n";
#	if ($package eq 'main::user') {
#		foreach my $k (keys %{$self}) {
#			print $k . " => " . $self->{$k} . "\n";
#		}
#	}	


	my ($msg,$log,$log_name,$opts) = @_;
	if (!ref($opts)) { $opts = {}; }
	if (!$log) { 
		$log = $self->c->sysdata->{'LOG_FILE'};
	}

	my $cj_id = 0;
	if ($self->c->cval->{'CJ_ID'}) { $cj_id = $self->c->cval->{CJ_ID}; }
	if (!-d "/home/adult/logs/") { mkdir("/home/adult/logs"); }
	if (!defined $log_name) {
		$log = "/home/adult/logs/" . $cj_id . "." . $log;
	} else {
		$log = "/home/adult/logs/" . $log;
	}
	
	my $ip = '';
	if (ref($self->c->env) && exists($self->c->env->{'REMOTE_ADDR'})) {
		$ip = $self->c->env->{'REMOTE_ADDR'}; 
	}
	if (!defined($msg)) { 
		my ($package,   $filename, $line,       $subroutine)   = caller(1);

		$msg = "msg undef: caller: $package $filename $line $subroutine $log";
	}

	#print STDERR "writing to $log\n";
	#syswrite $self->c->log_pool->{$log},   "[" . scalar localtime . " $ip ] " . $msg . "\n";
	my $web = '';
	if ($self->c->cval->{WEB}) { $web = $self->c->env->{PATH_INFO}; }
#	write_file($log, {binmode => ':utf8', append => 1},"[" . scalar localtime . " " . $ip . " " . $web . "] " . $msg . "\n");
	write_file($log, {append => 1},"[" . scalar localtime . " " . $ip . " " . $web . "] " . $msg . "\n");
}

sub build_query
{
	my $self = shift;
	my $data = shift;

	my $str = '';

	foreach (keys %{$data}) {
		$str .= $_ . "=" . $data->{$_} . "&";
	}
	$str =~ s/\&$//;
	
	return $str;
}

sub parse_query
{
	my $self = shift;
	my $data = shift;

	my %hash = ();
	my @pairs = split("&", $data);
	foreach (@pairs) {
		my ($key,$val) = split(/=/, $_);
		if ($key && $val) { $hash{$key} = $val; }
	}

	return \%hash;

}
sub redirect
{
	my $self = shift;
	my $url = shift;
	my $code = shift;
	my $options = shift || {};
	#print STDERR "redirect to $url" if ($self->c->env->{HTTP_USER_AGENT} =~ /HostTracker/);
	##$self->logger("red: " .$url);

	my $headers = {
		'Expires' => HTTP::Date::time2str(0),
		'Date' => HTTP::Date::time2str(time),
		'Cache-Control' => 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0',
		'Pragma' => 'no-cache',
		'Content-Type' => 'text/html; charset=utf-8',
	};
	if (exists($options->{headers}) && ref($options->{headers})) {
		foreach (keys %{$options->{headers}}) {
			$headers->{$_} = $options->{headers}->{$_};
		}
	}
	$self->c->res->headers($headers);
	
	if (defined($self->c->cval->{OUT_DOMAIN}) && $self->c->cval->{OUT_DOMAIN} && $url !~ /^http/) {
		$url = "http://" . $self->c->in->{cj_hash}->{domain} . $url;
	} 

	if (defined($code)) {
		$self->c->res->redirect($url,$code);
	} else {
		$self->c->res->redirect($url);
	}
#	print "Location: " . $url . "\r\n\r\n";
#	$self->exit_destr();
}

#sub get_random_str_simpel { join'', @_[ map{ rand @_ } 1 .. shift ] }


sub get_random_str2{
	my $self = shift;
	my $pattern = shift;
	
	return random_regex($pattern);
}

sub get_random_str
{
	my $self = shift;
	my $chars = shift;
	my $data;
	if ($chars !~ /^\d+$/) { $chars = 10; }

	open(R,"< /dev/urandom");
	read R, $data, int($chars/2);
	close(R);
	return unpack("H*", $data);
}




sub fetch_sql_hash
{
	my $self = shift;

	my $value = shift;
	my $key = shift;
	my $table = shift;
	my $where = shift || '';
	
	if ($key eq 'id' && !$value) { $value = 0; }

	my $hash = undef;

	my $cmd = "select * from $table where $key = ? $where limit 1";
	my $res = $self->c->db->prepare_cached($cmd);
	$res->execute($value) || $self->error("SQL: $cmd, " . $res->errstr);
	if ($res->rows eq 1) {
		$hash = $res->fetchrow_hashref;
	}
	$res->finish;

	#print STDERR "from hash: " . Dumper($hash);
	return $hash;
}

sub next_insert_id
{
	my $self = shift;
	my $table = shift;

	my $cmd = "show table status LIKE '$table'";
	my $res = $self->c->db->prepare($cmd);
	$res->execute || $self->error("SQL: $cmd, " . $res->errstr);
	my $hash = $res->fetchrow_hashref;
	$res->finish;
	
	return $hash->{'Auto_increment'};
}

sub next_seq_id
{
	my $self = shift;
	my $table = shift;

	return $self->mysql_cmd("select nextval('" . $table . "_id_seq')");
}


sub last_insert_id
{
	my $self = shift;
	
	return $self->mysql_cmd("select lastval()");
}

sub mysql_cmd_old
{
	my $self = shift;
	my $cmd = shift;
	my $bind = shift;
	
	my $data = undef;
	
	if (!ref($bind)) { $bind = []; }

	if ($cmd =~ /^[\r\n\s\t]*select/i) {
#		$self->logger("Using select method");
		my $res = $self->c->db->prepare($cmd);
#		$self->logger($cmd . " bind: " . Dumper($bind));
		$res->execute(@{$bind}) || $self->error("SQL: $cmd, " . $res->errstr);
		if ($res->rows) { $data = $res->fetchrow_array; }
		$res->finish;	
		
	} else {
		#$self->logger("Using do method $cmd");
		$data = $self->c->db->do($cmd,undef,@{$bind});
	}

	return $data;
}

sub mysql_cmd
{
	my $self = shift;
	my $cmd = shift;
	my $bind = shift;
	my $options = shift;

	my $data = undef;

	my $db = $self->c->db;
	if ($options->{db}) { $db = $options->{db}; }
	
	if (!ref($bind)) { $bind = []; }

#	if ($cmd =~ /^[\r\n\s\t]*select/i) {
#		$self->logger("Using select method");
		my $res = $db->prepare_cached($cmd);
#		$self->logger($cmd . " bind: " . Dumper($bind));
		if (ref($bind->[0]) eq 'HASH') {
			my $i = 1;
			foreach (@{$bind}) {
				$res->bind_param($i,$_->{value},$_->{type});
				$i++
			}
			if (ref($options) && exists($options->{raise_error})) {
				$res->execute || say STDERR $res->errstr;
			} else { $res->execute; } # || do { if ($self->c->cval->{SYSTEM}) { print STDERR $res->errstr; } };
		} else {
			if (ref($options) && exists($options->{raise_error})) {
				$res->execute(@{$bind}) || say STDERR "err in res: $cmd " . join(",", @{$bind}) . " " . $res->errstr;
			} else { $res->execute(@{$bind}); } # || do { if ($self->c->cval->{SYSTEM}) { print STDERR $res->errstr; } };

#			$res->execute(@{$bind}); # || do { if ($self->c->cval->{SYSTEM}) { print STDERR $res->errstr; } };
		}
#		$res->execute(@{$bind}) || $self->error("SQL: $cmd, " . $res->errstr);
		if ($cmd =~ /^[\r\n\s\t]*select/i && $res->rows) {
			if (ref($options) && exists($options->{array})) {
				my @data = $res->fetchrow_array;
				$res->finish;
				return @data;
			} else {
				$data = $res->fetchrow_array;
				$res->finish;
				return $data;				
			}
		}
		#if ($cmd =~ /select id from sources where cj_id = \? and type = 0 and short_name = 'other'/) { say "main cmd $cmd, data: $data"; }		
		$res->finish;	
		
#	} else {
		#$self->logger("Using do method $cmd");
#		$data = $self->c->db->do($cmd,undef,@{$bind});
#	}

	return $data;
}

sub mysql_cmd_array
{
	my $self = shift;
	my $cmd = shift;
	my $bind = shift;
	my $options = shift || {};

	if (ref($bind) ne 'ARRAY') { $bind = []; }


	my $db = $self->c->db;
	if ($options->{db}) { $db = $options->{db}; }	
	
	my $res = $db->prepare_cached($cmd);
	$res->execute(@{$bind}) || $self->error("SQL: $cmd, " . $res->errstr);
	my @data = ();

	while(my($value) = $res->fetchrow_array) {
		push @data, $value;
	}
	$res->finish;
	
	return \@data;		
}

sub get_curdate
{
        my $self = shift;
        my $offset = shift || 0;
        my $time = shift || time;

        my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($time + $offset);
        $mon++;
        $year += 1900;

        if ($mon < 10) { $mon = "0" . $mon; }
        if ($mday < 10) { $mday = "0" . $mday; }

        return $year . "-" . $mon . "-" . $mday;
}

sub exit_destr
{
	my $self = shift;
	#$self->logger("destr called:" . $self->c->cval->{'DESTR'});
	
	if ($self->c->cval->{'DESTR'}) { return; }
	
	$self->c->cval->{'DESTR'} = 1;

	#my $bot_regexp = $self->c->sysdata->{'bot_regexp'};

	
	#$self->logger("SESSION ref: " .  ref $self->c->session);
	
	if ($self->c->cval->{WEB}) {
		if ($self->c->cval->{BOT} && ref($self->c->session)) {
#		if ($self->c->env->{'HTTP_USER_AGENT'} =~ /$bot_regexp/i && ref $self->c->session eq 'CGI::Session') {
#			$self->c->session->expire();
#			$self->c->session->flush();
#			$self->logger("cleaning bot");
		} elsif (ref $self->c->session eq 'CGI::Session') {
			$self->c->session->flush();
		}
	}


	if (ref $self->c->db eq 'Apache::DBI::db' || ref $self->c->db eq 'DBI::db')	{
		#$self->logger("disconnection db, system: " . $self->c->cval->{'SYSTEM'} . "\n");
		if ($self->c->cval->{'SYSTEM'}) { $self->c->db->disconnect; }
		
#		$self->c->db->disconnect if (!$self->c->env->{'MOD_PERL'});
#		undef $self->{db};
	}
	
	if ($self->c->env->{'MOD_PERL'}) {
		ModPerl::Util::exit(0);
	} else {
		if ($self->c->cval->{'SYSTEM'}) { exit; }
		return 1;
#		exit(0);
	}
}


sub prepare_word
{
	my $self = shift;
	my $w = shift;
	my $opts = shift;
	
	if (!defined($w) || !$w) { return ''; }

	if ($opts->{'chomp'}) {
		$w =~ s/[\r\n]*//gism;
	}

	if ($opts->{'strip'}) {
		$w =~ s/^\s+//g;
		$w =~ s/\s$//g;
		$w =~ s/\s+/ /g;
	}
	
	if (exists($opts->{uc})) {
		$w = uc($w);
	}
	if (exists($opts->{lc})) {
		$w = lc($w);
	}
	if (exists($opts->{ucf})) {
		$w = ucfirst($w);
	}
	if ($opts->{'ucb'}) {
		$w = lc($w);
		$w =~ s/(^| )(\p{Punct}*)(\w)/$1$2\U$3/g;
	}


	return $w;
}

sub str_replace
{
	my $self = shift;
	my ($in,$pattern,$what,$options) = @_;

	if (!ref($options)) { $options = {}; }

	if (!defined($in) || !$in) { return ''; }
	if (!defined($pattern) || !$pattern) { return $in; }
	if (!defined($what)) { $what = ''; }

	if (exists($options->{g})) {
		$in =~ s/$pattern/$what/g;
	} else {
		$in =~ s/$pattern/$what/;
	}
	return $in;
}


sub get_url_curl
{
        my $self = shift;

        my $conf = shift;
        my $timeout = $conf->{'timeout'} || 30;
        my $agent = $conf->{'agent'} || "Mozilla/5.0 (Windows NT 6.1; rv:32.0) Gecko/20100101 Firefox/32.0";

        my $body = '';
        my $headers = '';
        my $error = '';
        my $debug = '';

        my $followlocation = 1;
        
        no strict qw(subs);

#        if (!is_class_loaded('WWW::Curl::Easy')) {#
#	        load_class('WWW::Curl::Easy');
#	        WWW::Curl::Easy->import();
#	    }

        if (exists($conf->{'followlocation'})) {
                $followlocation = $conf->{'followlocation'};
        }

#       print "g: " . $main::curl_global;
        my $curl = WWW::Curl::Easy->new();
        print STDERR $curl if ($conf->{'debug'});
        if ($conf->{'debug'}) {
                foreach (keys %{$conf}) {
                        print STDERR $_ . " => " . $conf->{$_} . "\n";
                }
        }
        
        my $fh;
        if ($conf->{'file'}) {
			open($fh, "> " . $conf->{'file'});
        }

        $curl->setopt(CURLOPT_NOPROGRESS, 1);
        $curl->setopt(CURLOPT_HEADER, 0);
        $curl->setopt(CURLOPT_AUTOREFERER, 1);
        $curl->setopt(CURLOPT_VERBOSE, 0);
        if ($conf->{'debug'}) {
                $curl->setopt(CURLOPT_VERBOSE, 1);
        }
        if ($conf->{'head'}) {
         	$curl->setopt(CURLOPT_NOBODY,1);
        }
#        $curl->setopt(CURLOPT_HEADERFUNCTION, \&body_callback);
#        $curl->setopt(CURLOPT_WRITEFUNCTION, \&body_callback);
#        $curl->setopt(CURLOPT_WRITEHEADER, \@header);
                $curl->setopt(CURLOPT_WRITEDATA, \$body);
                $curl->setopt(CURLOPT_WRITEHEADER, \$headers );

		if ($conf->{'file'}) {
			$curl->setopt(CURLOPT_FILE, $fh );
		}
                
        $curl->setopt(CURLOPT_ERRORBUFFER, $error);
        $curl->setopt(CURLOPT_MAXREDIRS, 4);
        $curl->setopt(CURLOPT_SSL_VERIFYPEER, 0);
        $curl->setopt(CURLOPT_SSL_VERIFYHOST, 0);
        $curl->setopt(CURLOPT_NOSIGNAL, 1);

        if ($conf->{'sslv'}) {
                if ($conf->{'sslv'} eq 2) {
                        $curl->setopt(CURLOPT_SSLVERSION,2);
                } elsif ($conf->{'sslv'} eq 3) {
                        $curl->setopt(CURLOPT_SSLVERSION,3);
                }
        }

        $curl->setopt(CURLOPT_FOLLOWLOCATION, $followlocation);

                if (ref($conf->{'header'}) eq 'ARRAY') {
                        $curl->setopt(CURLOPT_HTTPHEADER,$conf->{'header'});
                }
        if ($conf->{'cookie'}) {
                $curl->setopt(CURLOPT_COOKIE, $conf->{'cookie'});
        }
        if ($conf->{'preserve_cookie'}) {
		        $curl->setopt(CURLOPT_COOKIEFILE, "");	
        }
        if ($conf->{'auth'}) {
                $curl->setopt(CURLOPT_USERPWD, $conf->{'auth'});
        }
        if ($conf->{'proxy_auth'}) {
                $curl->setopt(CURLOPT_PROXYUSERPWD, $conf->{'proxy_auth'});
        }

#        $curl->setopt(CURLOPT_TIMEOUT, $timeout);
#        $curl->setopt(CURLOPT_CONNECTTIMEOUT, $timeout);

        $curl->setopt(CURLOPT_TIMEOUT_MS, $timeout * 1000);
        $curl->setopt(CURLOPT_CONNECTTIMEOUT_MS, $timeout * 1000);


        $curl->setopt(CURLOPT_USERAGENT, $agent);

        if (exists($conf->{'method'}) && lc($conf->{'method'}) eq 'post') {
                $curl->setopt(CURLOPT_POST, 1);
                if (ref($conf->{'post_fields'}) ne 'HASH' && !exists($conf->{'post_str'})) {
                        $curl->setopt(CURLOPT_POSTFIELDS, 'ap=ap');
                }
        }
			
        if (ref($conf->{'post_fields'}) eq 'HASH') {
                        my $str = '';
                        foreach (keys %{$conf->{'post_fields'}}) {
                                $str .= $_ . "=" . uri_escape($conf->{'post_fields'}->{$_}) . "&";
                        }
                        if (lc($conf->{'method'}) eq 'post') {
                                $curl->setopt(CURLOPT_POSTFIELDS, $str);
                        } else {
                                $conf->{'url'} .= "?" . $str
#                               $curl->setopt(CURLOPT_URL, $conf->{'url'} . "?" . $str);
                        }
        } elsif (exists($conf->{'post_str'})) {
                $curl->setopt(CURLOPT_POSTFIELDS, $conf->{'post_str'});
        }

        if ($conf->{'referer'}) {
                $curl->setopt(CURLOPT_REFERER, $conf->{'referer'});
        }

        if ($conf->{'proxy_type'}) {
                $curl->setopt(CURLOPT_PROXYTYPE, $conf->{'proxy_type'});
        }
        if ($conf->{'proxy'}) {
                $curl->setopt(CURLOPT_PROXY, $conf->{'proxy'});
        }
        if ($conf->{'int'}) {
                $curl->setopt(CURLOPT_INTERFACE, $conf->{'int'});
        }

        $curl->setopt(CURLOPT_URL, $conf->{'url'});

#               print STDERR Dumper($conf);
#               print STDERR Dumper($curl);

        my $ret = $curl->perform;

        if ($conf->{'file'}) {
			close($fh);
        }
                my %hashr = ();

#       print "ref: $ret\n";
        if ($ret) {
                                %hashr = (
                                        err => $ret,
                                        err_msg => $curl->strerror($ret)
                                );
        } else {
                                #print "body: " . $body . "\n";
                                #print Dumper($curl);
                                %hashr = (
                                        body => $body,
                                        headers => $headers,
                                        code => $curl->getinfo(CURLINFO_HTTP_CODE),
                                        eff_url => $curl->getinfo(CURLINFO_EFFECTIVE_URL),
                                );
                                #print Dumper(%hashr);
        }
#        $curl->cleanup();
#       print $body;
 #       print Dumper(%hash);
        return \%hashr;
}

#sub DESTROY {
#	my $self = shift;
#	$self->logger("DESTROY called");
#	$self->exit_destr();
#}
__PACKAGE__->meta->make_immutable;
1;
