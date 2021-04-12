package EdgeOSAPI;
require Exporter;
@ISA    = qw(Exporter);
@EXPORT = qw();


use IO::Socket::SSL;
IO::Socket::SSL::set_ctx_defaults(verify_mode=>0);

use LWP::UserAgent; use HTTP::Cookies; use JSON;

sub new {
    my $this = shift;
    my ($host,$user,$pass) = @_;
    my $class = ref($this) || $this;
    my $self = {};
    bless($self, $class);

    $self->{host} = $host;
    $self->{sessionid} = $self->login($user,$pass);
    
    return $self;
}

sub login {
    my $self = shift;
    my ($user, $pass) = @_;
    my $url = "https://$self->{host}";
    my $res = $self->doQuery($url,undef,{postData=>"username=$user&password=$pass"});
    
    return;
}

sub logout {
    my $self = shift;
    my $url = "https://$self->{host}/logout";
    my $res = $self->doQuery($url);
    return;
}

sub get_dhcp_leases {
    my $self = shift;
    my $res = $self->doQuery("https://$self->{host}/api/edge/data.json?data=dhcp_leases");
    my $hash = decode_json($res->content);
    my $all = {};
    if ($hash->{success}) {
	my $leases = $hash->{output}->{'dhcp-server-leases'};
	foreach my $name (sort keys %{$leases}) {
	    foreach my $ip (sort keys %{$leases->{$name}}) {
		$all->{$ip} = $leases->{$name}->{$ip};
	    }
	}
    }
    return $all;
}

sub doQuery {
    my $self = shift;
    my ($url, $params, $flags) = @_;

    my $ua = $self->{ua} || new LWP::UserAgent(ssl_opts=>{verify_hostname=>0,});
    $self->{ua} = $ua;
    $ua->timeout(15);
    $self->{cookies} = HTTP::Cookies->new() unless defined($self->{cookies});
    $ua->cookie_jar($self->{cookies});
    if ($flags->{postData}) {
	$req = new HTTP::Request 'POST', $url;
	$req->content($flags->{postData});
    }
    else {
	$req = new HTTP::Request 'GET', $url;
    }
    my $res = $ua->request($req);
    return $res;
}

1;
