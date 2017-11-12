#!/usr/bin/perl


use Modern::Perl;
use Time::HiRes qw(gettimeofday tv_interval);
use Data::Dumper;
use File::Slurp;
use Locale::Codes::Country;
use JSON::XS;
use DBD::mysql;
use POSIX qw/strftime/;

use lib qw(/home/adult/engine);

use main;
use main::config;
my $c = new main::config;
my $main = new main(c=>$c);


chdir("/home/adult/engine");

$c->cval->{SYSTEM} = 1;


my $db = dbp();
my $cmd = "select * from accounts order by id";
my $res = $db->prepare($cmd);
$res->execute;
while(my $hash = $res->fetchrow_hashref) {
	if ($ARGV[0] && $hash->{id} ne $ARGV[0]) { next; }
	if ($hash->{btype} eq 1) { check_exo($hash); }
	if ($hash->{btype} eq 2) { check_clickadu($hash); }
	if ($hash->{btype} eq 4) { check_ero($hash); }
	if ($hash->{btype} eq 8) { check_terra($hash); }
	if ($hash->{btype} eq 6) { check_hill($hash); }
	if ($hash->{btype} eq 11) { check_tshop($hash); }
}
$res->finish;

sub check_tshop
{
	my $hash = shift;

	my $yesterday = strftime('%d.%m.%Y',localtime(time - 86400) );
	my $yesterday_old = $main->get_curdate(-86400);

	my $data = {
		mail => $hash->{auth1},
		password => $hash->{auth2},
		form_mode => 'save',
		active_form => 'login'
	};
	my $r_hash = $main->get_url_curl({ debug => 1, url => "https://beta.trafficshop.com/publisher/login", agent => 'stats collector'});
	my $cookies = $main->parse_cookies_header($r_hash->{headers});
	my $cookie_str;
	foreach (keys %{$cookies}) {
			$cookie_str .= $_ . "=" .$cookies->{$_} . "; ";
	}
	print Dumper($r_hash);
	$r_hash = $main->get_url_curl({ debug => 1, cookie => $cookie_str, method => 'POST', post_fields => $data, url => "https://beta.trafficshop.com/publisher/login/timeout", agent => 'stats collector'});

	$data = {
		manage_sites_per_page => 200,
		id => 'sites_channels',
		active_form => 'manage_sites_form',
		status_filter => 'all',
		period => 'today',
		mode => 'select'
	};

	my $sids = {};

	$r_hash = $main->get_url_curl({ debug => 0, cookie => $cookie_str, method => 'POST', post_fields => $data, url => "https://beta.trafficshop.com/publisher/manage_sites_channels", agent => 'stats collector'});
	#print $r_hash->{body};

	foreach my $line (split(/\n/, $r_hash->{body})) {
		my ($sid,$domain);
		if ($line =~ m{edit_site/index/(\d+)}) {
			$sid = $1;
		}
		if ($line =~ m{([\w\-\.]+)</td><td class="w80}) { $domain = $1; }
		if ($sid) {
			print $sid . " - " . $domain . "\n";
			$sids->{$sid} = $domain;
		}
	}
#https://beta.trafficshop.com/publisher/detailed_stats

	foreach my $sid (keys %{$sids}) {
		#if ($sids->{$sid} ne 'whitexxxtube.com') { next; }
		#print "domain: $sids->{$sid}\n";
		my $data = {
			mode => 'range',
			from => $yesterday,
			to => $yesterday,
			domains => $sids->{$sid},
			type => 'all',
			id => 'pub_detail_stat_reqreports_formm',
			active_form => 'pub_detail_stat_reqreports_formm',
		};
		$r_hash = $main->get_url_curl({ debug => 0, cookie => $cookie_str, method => 'POST', post_fields => $data, url => "https://beta.trafficshop.com/publisher/detailed_stats", agent => 'stats collector'});
#		print Dumper($r_hash);
#		exit;
		my $item = {};
		foreach my $line (split(/\n/, $r_hash->{body})) {
			if ($line =~ m{$yesterday_old</td><td class="pl10" data-row="2" >(\d+)</td><td class="pl10" data-row="2" >(\d+)</td><td class="pl10" data-row="2" >\d+.\d+%</td><td class="pl10" data-row="2" >\$(\d+\.\d+)</td><td class="pl10" data-row="2" >\d+</td><td class="pl10" data-row="2" >\$(\d+\.\d+)</td><td class="pl10" data-row="2" >(\d+)</td><td class="pl10" data-row="2" >(\d+)</td><td class="pl10" data-row="2" >\d+%</td><td class="pl10" data-row="2" >\d+</td><td class="pl10" data-row="2" >\$(\d+\.\d+)</td><td class="pl10" data-row="2" >\$(\d+\.\d+)</td>})
			{
				$item->{ban_imp} = $1;
				$item->{ban_clicks} = $2;
				$item->{ban_cpm} = $3;
				$item->{ban_amount} = $4;

				$item->{pop_imp} = $5;
				$item->{pop_paid} = $6;
				$item->{pop_cpm} = $7;
				$item->{pop_amount} = $8;

				last;
			}	
		}

		my $sql_data = {
			ts => $main->get_curdate(-86400),
			site_id => $sid,
			zone_id => 0,
			imp => $item->{ban_imp} || 0,
			clicks => $item->{ban_clicks} || 0,
			cpm => $item->{ban_cpm} || 0,
			amount => $item->{ban_amount} || 0,
			z_type => 2,
			t_type => 1,
			bid => $hash->{id}
		};

		my($stmt, @bind) = $c->sql->insert('stats', $sql_data);
		my $ress = $db->prepare($stmt) || die $DBI::errstr;
		$ress->execute(@bind) || die $ress->errstr;
		$ress->finish;


		$sql_data = {
			ts => $main->get_curdate(-86400),
			site_id => $sid,
			zone_id => 0,
			imp => $item->{pop_imp} || 0,
			clicks => $item->{pop_clicks} || 0,
			cpm => $item->{pop_cpm} || 0,
			amount => $item->{pop_amount} || 0,
			z_type => 1,
			t_type => 1,
			bid => $hash->{id}
		};

		($stmt, @bind) = $c->sql->insert('stats', $sql_data);
		$ress = $db->prepare($stmt) || die $DBI::errstr;
		$ress->execute(@bind) || die $ress->errstr;
		$ress->finish;

		#print Dumper($item);

	}


	#print Dumper($sids);
}

sub check_hill
{
	my $hash = shift;

	


	my $data = {
			key => $hash->{auth3},
	};
	#print Dumper($data);
	
	my $r_hash = $main->get_url_curl({ debug => 0, method => 'GET', url => "https://hilltopads.com/api/publisher/inventory?" . $main->build_query($data)});

	my $json_data = eval { decode_json($r_hash->{body}); };
	if ($@ || !ref($json_data) || $json_data->{status} ne 'success') { print "bad data $@ $r_hash->{body}\n"; return; }




	foreach my $sid (keys %{$json_data->{result}->{sites}}) {

		$data = {
			key => $hash->{auth3},
			date => $main->get_curdate(-86400),
			siteId => $sid
		};

		$r_hash = $main->get_url_curl({ debug => 0, method => 'GET', url => "https://hilltopads.com/api/publisher/zones?" . $main->build_query($data)});

		my $json_data2 = eval { decode_json($r_hash->{body}); };
		if ($@ || !ref($json_data2) || $json_data2->{status} ne 'success' || ref($json_data2->{result}) ne 'HASH') { next; }

		#print STDERR Dumper($json_data2);

		my $imp = 0;
		my $cpm = 0;
		my $clicks = 0;
		my $amount = 0;

		foreach my $zid (keys %{$json_data2->{result}}) {
			$imp += $json_data2->{result}->{$zid}->{impressions};
			#$clicks += $json_data->{result}->{zid}->{impressions};
			$cpm = $json_data2->{result}->{$zid}->{cpm};
			$amount += $json_data2->{result}->{$zid}->{revenue};
		}



		my $sql_data = {
			ts => $main->get_curdate(-86400),
			site_id => $sid,
			zone_id => 0,
			imp => $imp || 0,
			clicks => $clicks || 0,
			cpm => $cpm || 0,
			amount => $amount || 0,
			z_type => 1,
			t_type => 1,
			bid => $hash->{id}
		};

		my($stmt, @bind) = $c->sql->insert('stats', $sql_data);
		my $ress = $db->prepare($stmt) || die $DBI::errstr;
		$ress->execute(@bind) || die $ress->errstr;
		$ress->finish;



	}

#	print $r_hash->{body};
}

sub parse_hill_html
{
	my $html = shift;
	my @token = ();
	my $res = {};

	my $i = 0;
	my $date = $main->get_curdate(-86400);

	#print $html;
	foreach my $line (split(/\n/, $html)) {
		#print "$i $line \n" if ($i);
		if ($line =~ m{id="csrfToken" type="hidden" name="(.*?)" value="(.*?)"}) {
			#print "token line\n";
			$token[0] = $1;
			$token[1] = $2;
		}
		if ($line =~ /<td><nobr>$date/) {
			$i = 1; next;
		}
		if ($i == 1) { ($res->{imp}) = $line =~ /(\d+)/; $i++; next; }
		if ($i == 4) { ($res->{clicks}) = $line =~ /(\d+)/; $i++; next; }
		if ($i == 10) { ($res->{amount}) = $line =~ /(\d+\.\d+)/; $i++; }
		if ($i == 10) { ($res->{amount}) = $line =~ /(\d+\.\d+)/; $i++; }
		if ($i == 17) { ($res->{cpm}) = $line =~ /(\d+\.\d+)/; last; }
		$i++ if ($i);

	}

	return ($token[0],$token[1],$res);
}

sub check_terra
{
	my $hash = shift;

	my $r_hash =  $main->get_url_curl({ debug => 0, url => "https://api.adsterratools.com/publisher/" . $hash->{auth1} . "/placements.json"});
	if ($r_hash->{code} ne 200) { return undef; }
	my $json = eval { decode_json($r_hash->{body}); };
	if ($@ || !ref($json)) { return; }
	
	#print Dumper($json);

	my $sum = 0;

	foreach my $item (@{$json->{items}}) {
		#print "item: " . Dumper($item);

		if (!$item->{domain_id}) { next; }
		my $data = {
			placement => $item->{id},
			start_date => $main->get_curdate(-86400),
			finish_date => $main->get_curdate(-86400),
			group_by => 'placement',
		};

		$r_hash =  $main->get_url_curl({ debug => 0, url => "https://api.adsterratools.com/publisher/" . $hash->{auth1} . "/stats.json?" . $main->build_query($data)});
		#say "https://api.adsterratools.com/publisher/" . $hash->{auth1} . "/stats.json?" . $main->build_query($data);
		if ($r_hash->{code} ne 200) { 
			#say "https://api.adsterratools.com/publisher/" . $hash->{auth1} . "/stats.json?" . $main->build_query($data);
			print Dumper($r_hash);  next;
		}
		my $json2 = eval { decode_json($r_hash->{body}); };
		if ($@ || !ref($json2) || ref($json2->{items}) ne 'ARRAY') { 
			#say "https://api.adsterratools.com/publisher/" . $hash->{auth1} . "/stats.json?" . $main->build_query($data);
			#print Dumper($r_hash); 
			next;
		}

		my $item_data = $json2->{items}->[0];
		if (ref($item_data) ne 'HASH') { 
			#say "https://api.adsterratools.com/publisher/" . $hash->{auth1} . "/stats.json?" . $main->build_query($data);
			#print STDERR "null item: " . Dumper($json2);
			next;
		}
		#$sum += $item_data->{revenue};
		#say $item_data->{revenue} . " sum: " . $sum;
		my $sql_data = {
			ts => $main->get_curdate(-86400),
			site_id => $item->{domain_id},
			zone_id => $item->{id},
			imp => $item_data->{impressions} || 0,
			clicks => $item_data->{clicks} || 0,
			cpm => $item_data->{cpm} || 0,
			amount => $item_data->{revenue} || 0,
			z_type => 1,
			t_type => 1,
			bid => $hash->{id}
		};
		if (!$ARGV[1]) {
			my($stmt, @bind) = $c->sql->insert('stats', $sql_data);
			my $ress = $db->prepare($stmt) || die $DBI::errstr;
			$ress->execute(@bind) || die $ress->errstr;
			$ress->finish;
		}
	}

}

sub check_ero
{
	my $hash = shift;

	my $data = {
		hash => $hash->{auth1},
		datestart =>$main->get_curdate(-86400),
		dateend => $main->get_curdate(-86400),
		sumresults => 1,
		selcols => 'adtype,siteid,spaceid,traffic_type'
	};
	my $r_hash = $main->get_url_curl({ debug => 0, url => "https://userpanel.ero-advertising.com/apitool/publisher/stats/details", method => 'POST', post_fields => $data});
	#print Dumper($r_hash);

	if ($r_hash->{code} ne 200) { return undef; }
	my $json = eval { decode_json($r_hash->{body}); };
	if ($@ || !ref($json)) { return; }

	my $result = {};

#	print Dumper($json);

	foreach my $res (@{$json->{data}->{stats}}) {
		if (!$res->{siteid}) { next; }
		$res->{earned} = $res->{earned} / 100;

		if ($res->{adtype_name} eq 'bannerads') {
			if ($res->{traffic_type_name} eq 'Web') {
				$result->{ $res->{spaceid} }->{ban}->{desk}->{amount} += $res->{earned};
				$result->{ $res->{spaceid} }->{ban}->{desk}->{clicks} += $res->{clicks};
				$result->{$res->{spaceid} }->{ban}->{desk}->{imp} += $res->{views};
			} else {
				$result->{ $res->{spaceid} }->{ban}->{mob}->{amount} += $res->{earned};
				$result->{ $res->{spaceid} }->{ban}->{mob}->{clicks} += $res->{clicks};
				$result->{$res->{spaceid} }->{ban}->{mob}->{imp} += $res->{views};				
			}
		}

		if ($res->{adtype_name} eq 'popads' || $res->{adtype_name} eq 'speedclicks') {
			if ($res->{traffic_type_name} eq 'Web') {
				$result->{ $res->{spaceid} }->{pop}->{desk}->{amount} += $res->{earned};
				$result->{ $res->{spaceid} }->{pop}->{desk}->{clicks} += $res->{clicks};
				$result->{$res->{spaceid} }->{pop}->{desk}->{imp} += $res->{views};
			} else {
				$result->{ $res->{spaceid} }->{pop}->{mob}->{amount} += $res->{earned};
				$result->{ $res->{spaceid} }->{pop}->{mob}->{clicks} += $res->{clicks};
				$result->{$res->{spaceid} }->{pop}->{mob}->{imp} += $res->{views};				
			}
		}
		
	}

	$data = {
		hash => $hash->{auth1},
		sumresults => 1,
	};
	$r_hash = $main->get_url_curl({ debug => 0, url => "https://userpanel.ero-advertising.com/apitool/publisher/adspaces/getlist", method => 'POST', post_fields => $data});
	#print Dumper($r_hash);

	if ($r_hash->{code} ne 200) { return undef; }
	$json = eval { decode_json($r_hash->{body}); };
	if ($@ || !ref($json)) { return; }

	foreach my $res (@{$json->{data}->{adspaces}}) {
		if (!$res->{siteid}) { next; }
		my $sql_data = {
			ts => $main->get_curdate(-86400),
			site_id => $res->{siteid},
			zone_id => $res->{id},
			imp => $result->{ $res->{id} }->{pop}->{desk}->{imp} || 0,
			clicks => $result->{ $res->{id} }->{pop}->{desk}->{clicks} || 0,
			cpm => 0.0,
			amount => $result->{ $res->{id} }->{pop}->{desk}->{amount} || 0,
			z_type => 1,
			t_type => 1,
			bid => $hash->{id}
		};

		my($stmt, @bind) = $c->sql->insert('stats', $sql_data);
		my $ress = $db->prepare($stmt) || die $DBI::errstr;
		$ress->execute(@bind) || die $ress->errstr;
		$ress->finish;

		$sql_data = {
			ts => $main->get_curdate(-86400),
			site_id => $res->{siteid},
			zone_id => $res->{id},
			imp => $result->{ $res->{id} }->{pop}->{mob}->{imp} || 0,
			clicks => $result->{ $res->{id} }->{pop}->{mob}->{clicks} || 0,
			cpm => 0.0,
			amount => $result->{ $res->{id} }->{pop}->{mob}->{amount} || 0,
			z_type => 1,
			t_type => 2,
			bid => $hash->{id}
		};

		($stmt, @bind) = $c->sql->insert('stats', $sql_data);
		$ress = $db->prepare($stmt) || die $DBI::errstr;
		$ress->execute(@bind) || die $ress->errstr;
		$ress->finish;
		
		$sql_data = {
			ts => $main->get_curdate(-86400),
			site_id => $res->{siteid},
			zone_id => $res->{id},
			imp => $result->{ $res->{id} }->{ban}->{mob}->{imp} || 0,
			clicks => $result->{ $res->{id} }->{ban}->{mob}->{clicks} || 0,
			cpm => 0.0,
			amount => $result->{ $res->{id} }->{ban}->{mob}->{amount} || 0,
			z_type => 2,
			t_type => 2,
			bid => $hash->{id}
		};

		($stmt, @bind) = $c->sql->insert('stats', $sql_data);
		$ress = $db->prepare($stmt) || die $DBI::errstr;
		$ress->execute(@bind) || die $ress->errstr;
		$ress->finish;


		$sql_data = {
			ts => $main->get_curdate(-86400),
			site_id => $res->{siteid},
			zone_id => $res->{id},
			imp => $result->{ $res->{id} }->{ban}->{desk}->{imp} || 0,
			clicks => $result->{ $res->{id} }->{ban}->{desk}->{clicks} || 0,
			cpm => 0.0,
			amount => $result->{ $res->{id} }->{ban}->{desk}->{amount} || 0,
			z_type => 2,
			t_type => 1,
			bid => $hash->{id}
		};

		($stmt, @bind) = $c->sql->insert('stats', $sql_data);
		$ress = $db->prepare($stmt) || die $DBI::errstr;
		$ress->execute(@bind) || die $ress->errstr;
		$ress->finish;


	}

}


sub check_exo
{
	my $hash = shift;

	my $data = encode_json({
		api_token => $hash->{auth1}
	});

	my $r_hash = $main->get_url_curl({ debug => 0, url => 'https://api.exoclick.com/v1/login', method => 'POST', header => ['Content-Type: application/json'], post_str => $data});
	if ($r_hash->{code} ne 200) { return undef; }

	my $token = eval { decode_json($r_hash->{body} )};

	$data = {
		limit => 500
	};

	$r_hash = $main->get_url_curl({ debug => 0, url => 'https://api.exoclick.com/v1/zones?' . $main->build_query($data) , method => 'GET', , header => ['Content-Type: application/json','Authorization: ' . $token->{type} . " " . $token->{token}]});
	if ($r_hash->{code} ne 200) { return; };
	my $json = eval { decode_json($r_hash->{body}); };
	if ($@ || ref($json->{result}) ne 'ARRAY') { return; }

	foreach my $z_hash (@{$json->{result}}) {

		#if ($z_hash->{idsite} ne 348430) { next; }

		$data = {
			zoneid => $z_hash->{id},
			'date-to' => $main->get_curdate(-86400),
			'date-from' => $main->get_curdate(-86400),
			limit => 100
		};

		my $result_mob = {
			ts => $main->get_curdate(-86400),
			site_id => $z_hash->{idsite},
			zone_id => $z_hash->{id},
			imp => 0,
			clicks => 0,
			cpm => 0.0,
			amount => 0.0,
			z_type => 1,
			t_type => 2,
			bid => $hash->{id}
		};

		my $result_desk = {
			ts => $main->get_curdate(-86400),
			site_id => $z_hash->{idsite},
			zone_id => $z_hash->{id},
			imp => 0,
			clicks => 0,
			cpm => 0.0,
			amount => 0.0,
			z_type => 1,
			t_type => 1,
			bid => $hash->{id}
		};

		if ($z_hash->{ad_type} eq 2) {
			$result_mob->{z_type} = 2;
			$result_desk->{z_type} = 2;
		}


		$r_hash = $main->get_url_curl({ debug => 0, url => 'https://api.exoclick.com/v1/statistics/publisher/device?' . $main->build_query($data) , method => 'GET', , header => ['Content-Type: application/json','Authorization: ' . $token->{type} . " " . $token->{token}]});
		my $headers = $main->parse_headers($r_hash->{headers});
		if ($headers->{'X-Rate-Limit-Remaining'} < 10) {
			my $sleep = 60;
			if ($headers->{'X-Rate-Limit-Remaining'} < 5) { $sleep = 60 * 5; }
			print "Sleeping on rate limit : " . $headers->{'X-Rate-Limit-Remaining'} . " ($sleep) \n";
			sleep($sleep);
		}

		if ($r_hash->{code} ne 200) { next; };
		my $json = eval { decode_json($r_hash->{body}); };
		if ($@ || ref($json->{result}) ne 'ARRAY') { next; }

		foreach my $stat (@{$json->{result}}) {
			if ($stat->{iddevice} eq 0) {
				$result_desk->{imp} += $stat->{impressions};
				$result_desk->{clicks} += $stat->{clicks};
				$result_desk->{amount} += $stat->{revenue};
			} else {
				$result_mob->{imp} += $stat->{impressions};
				$result_mob->{clicks} += $stat->{clicks};
				$result_mob->{amount} += $stat->{revenue};
			}
		}
		$result_desk->{cpm} = $result_desk->{amount} / $result_desk->{imp} if ($result_desk->{imp});
		$result_mob->{cpm} = $result_mob->{amount} / $result_mob->{imp} if ($result_mob->{imp});


		my($stmt, @bind) = $c->sql->insert('stats', $result_mob);
		my $res = $db->prepare($stmt) || die $DBI::errstr;
		$res->execute(@bind) || die $res->errstr;
		$res->finish;

		($stmt, @bind) = $c->sql->insert('stats', $result_desk);
		$res = $db->prepare($stmt) || die $DBI::errstr;
		$res->execute(@bind) || die $res->errstr;
		$res->finish;

	}


}

sub check_clickadu
{
	my $hash = shift;

	my $data = {
		token => $hash->{auth1},
		dateFrom => $main->get_curdate(-3600 * 5 - 86400),
		dateTo => $main->get_curdate(-3600 * 5 - 86400),
		groupBy => 'site',

	};

	print "query: " . $main->build_query($data) . "\n";
	my $r_hash = $main->get_url_curl({ debug => 1, url => 'http://proxy.api.clickadu.com/partner/stats?' . $main->build_query($data)});
	if ($r_hash->{code} ne 200) { return undef; }

#	print Dumper(decode_json($r_hash->{body}));return;

	my $json = eval { decode_json($r_hash->{body}); };
	if ($@ || !ref($json)) { return; }
	
	print Dumper($json);

	my $sum = 0;

	foreach my $item (@{$json->{stats}}) {

		my $sql_data = {
			ts => $main->get_curdate(-3600 * 5 - 86400),
			site_id => $item->{site},
			zone_id => 0,
			imp => $item->{impressions} || 0,
			clicks => 0,
			cpm => 0,
			amount => $item->{money} || 0,
			z_type => 1,
			t_type => 1,
			bid => $hash->{id}
		};

		my($stmt, @bind) = $c->sql->insert('stats', $sql_data);
		my $ress = $db->prepare($stmt) || die $DBI::errstr;
		$ress->execute(@bind) || die $ress->errstr;
		$ress->finish;
	}




}

sub dbp
{
	return DBI->connect("DBI:mysql:dbname=pub_stats;host=127.0.0.1", "pub_stats", "pub_stats") || die $DBI::errstr;
}