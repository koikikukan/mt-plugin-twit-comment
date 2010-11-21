package TwitComment::App;

use strict;

use CGI;
use HTTP::Request::Common;
use LWP::UserAgent;
use Digest::SHA1;
use Net::OAuth;
use XML::Simple;
use MT::Util qw( ts2epoch decode_url );

sub handle_sign_in {
    my $app = shift;
    my ($class, $auth_type) = @_;

    my $q = $app->{query};
    my $oauth_token = $q->param('oauth_token');
    my $oauth_verifier = $q->param('oauth_verifier');
    my $blog_id = $q->param('blog_id');

    my $c = CGI->new;
    my %cookies = $c->cookie('TwitComment');
    my $request_token = $cookies{'token'};
    my $request_token_secret = $cookies{'token_secret'};
    my $static = $cookies{'static'};

    $app->bake_cookie(
        -name    => 'TwitComment',
        -value   => '',
        -expires => '-1y',
        -path    => '/'
    );

    my $access_token_url = 'https://api.twitter.com/oauth/access_token';
    my $request_method = 'POST';

    my $plugin = $app->component("TwitComment");
    my $consumer_key = $plugin->get_config_value('TwitComment_consumerkey', 'blog:' . $blog_id);
    my $consumer_secret = $plugin->get_config_value('TwitComment_consumerkey_secret', 'blog:' . $blog_id);

    my $request = Net::OAuth->request("access token")->new(
        consumer_key => $consumer_key,
        consumer_secret => $consumer_secret,
        request_url => $access_token_url,
        request_method => $request_method,
        signature_method => 'HMAC-SHA1',
        timestamp => time,
        nonce => Digest::SHA1::sha1_base64(time . $$ . rand),
        token => $oauth_token,
        verifier => $oauth_verifier,
        token_secret => $request_token_secret,
    );
    
    $request->sign;
    return $app->error('Signature verification failed! check OAuth parameters.',$blog_id)
        unless $request->verify;

    my $ua = LWP::UserAgent->new;
    my $http_hdr = HTTP::Headers->new('User-Agent' => 'TwitComment');
    my $http_req = HTTP::Request->new($request_method, $access_token_url, $http_hdr, $request->to_post_body);
    my $res = $ua->request($http_req);

    return $app->error('Signature verification failed! check OAuth parameters.',$blog_id)
        unless $res->is_success;

    my $response = Net::OAuth->response('access token')->from_post_body($res->content);

    my $access_token = $response->token;
    my $access_token_secret = $response->token_secret;
    my $user_id = $response->extra_params->{'user_id'};
    my $screen_name = $response->extra_params->{'screen_name'};

    # MT::Auth::OpenID::handle_sign_in
    my $INTERVAL = 60 * 60 * 24 * 7;

    $auth_type = 'TwitComment';

    my $blog = $app->model('blog')->load($blog_id);
    my $author_class = $app->model('author');

    my $cmntr;
    my $session;

    my %param = $app->param_hash;
    my $nickname = $param{'openid.sreg.nickname'};
    $param{'screen_name'} = Encode::encode_utf8($screen_name)
        if Encode::is_utf8($screen_name);

    $cmntr = $author_class->load(
        {
            name => $screen_name,
            type => $author_class->COMMENTER(),
            auth_type => $auth_type,
        }
    );
    if ( $cmntr ) {
        unless ( ( $cmntr->modified_on
            && ( ts2epoch($blog, $cmntr->modified_on) > time - $INTERVAL ) )
          || ( $cmntr->created_on
            && ( ts2epoch($blog, $cmntr->created_on) > time - $INTERVAL ) ) )
        {
            $cmntr->nickname($screen_name);
            $cmntr->save or return 0;
        }
    }
    else {
        $cmntr = $app->make_commenter(
            name        => $screen_name,
            url         => 'http://twitter.jp/'.$screen_name,
            auth_type   => $auth_type,
            external_id => _url_hash('http://twitter.jp/'.$screen_name),
        );
        if ($cmntr) {
            $cmntr->nickname($screen_name);
            $cmntr->save or return 0;
        }
    }
    return $app->error('Failure Commenter') unless $cmntr;

    # Signature was valid, so create a session, etc.
    $session = $app->make_commenter_session($cmntr);

    unless ($session) {
        $app->error($app->errstr() || $app->translate("Couldn't save the session"));
#        return 0;
        return $app->redirect(decode_url($static));
    }

    if (my $userpic = $cmntr->userpic) {
       require MT::FileMgr;
        my $fmgr = MT::FileMgr->new('Local');
        my $mtime = $fmgr->file_mod_time($userpic->file_path());
        if ( $mtime > time - $INTERVAL ) {
            # newer than 7 days ago, don't download the userpic
#            return $app->redirect(decode_url($static).'#_login');
        }
    }
    my $ua = LWP::UserAgent->new;
    my $url = "http://twitter.com/users/show/$screen_name.xml";
    my $res = $ua->get($url);
    if($res->is_success){
        my $xml = $res->content;
        my $data = XMLin($xml);
        my $image_url = $data->{profile_image_url};
        $image_url =~ s/_normal\./_bigger./; 
        if ( my $userpic = _asset_from_url($image_url) ) {
            $userpic->tags('@userpic');
            $userpic->created_by($cmntr->id);
            $userpic->save;
            if (my $userpic = $cmntr->userpic) {
                # Remove the old userpic thumb so the new userpic's will be generated
                # in its place.
                my $thumb_file = $cmntr->userpic_file();
                my $fmgr = MT::FileMgr->new('Local');
                if ($fmgr->exists($thumb_file)) {
                    $fmgr->delete($thumb_file);
                }

                $userpic->remove;
            }
            $cmntr->userpic_asset_id($userpic->id);
            $cmntr->save;
        }
    }

    return $app->redirect(decode_url($static).'#_login');

}

sub _url_hash {
    my ($url) = @_;

    if (eval { require Digest::MD5; 1; }) {
        return Digest::MD5::md5_hex($url);
    }
    return substr $url, 0, 255;
}

sub oauth_commenter_condition {
    my ( $blog, $reason ) = @_;
    return 1 unless $blog;

    eval "require Digest::SHA1;";
    return 0 if $@;
    eval "require Net::OAuth;";
    return 0 if $@;

    my $plugin = MT->component("TwitComment");
    my $consumer_key = $plugin->get_config_value('TwitComment_consumerkey', 'blog:' . $blog->id);
    my $consumer_secret = $plugin->get_config_value('TwitComment_consumerkey_secret', 'blog:' . $blog->id);

    unless ( $consumer_key && $consumer_secret ) {
        $$reason = 
           '<a href="?__mode=cfg_plugins&amp;blog_id=' . $blog->id . '">'
           . $plugin->translate('Set up TwitComment plugin')
           . '</a>';
        return 0;
    }
    return 1;
}

sub commenter_auth_params {
    my ($key, $blog_id, $entry_id, $static) = @_;

    my $url = "http://twitter.jp/";
    my $params = {
        blog_id => $blog_id,
        static  => $static,
        url     => $url,
    };
    $params->{entry_id} = $entry_id if defined $entry_id;
    return $params;
}

sub _get_ua {
    return MT->new_ua( { paranoid => 1 } );
}

sub _asset_from_url {
    my ($image_url) = @_;
    my $ua   = _get_ua() or return;
    my $resp = $ua->get($image_url);
    return undef unless $resp->is_success;
    my $image = $resp->content;
    return undef unless $image;
    my $mimetype = $resp->header('Content-Type');
    my $def_ext = {
        'image/jpeg' => '.jpg',
        'image/png'  => '.png',
        'image/gif'  => '.gif'}->{$mimetype};

    require Image::Size;
    my ( $w, $h, $id ) = Image::Size::imgsize(\$image);

    require MT::FileMgr;
    my $fmgr = MT::FileMgr->new('Local');

    my $save_path  = '%s/uploads/';
    my $local_path =
      File::Spec->catdir( MT->instance->support_directory_path, 'uploads' );
    $local_path =~ s|/$||
      unless $local_path eq '/';    ## OS X doesn't like / at the end in mkdir().
    unless ( $fmgr->exists($local_path) ) {
        $fmgr->mkpath($local_path);
    }
    my $filename = substr($image_url, rindex($image_url, '/'));
    if ( $filename =~ m!\.\.|\0|\|! ) {
        return undef;
    }
    my ($base, $uploaded_path, $ext) = File::Basename::fileparse($filename, '\.[^\.]*');
    $ext = $def_ext if $def_ext;  # trust content type higher than extension

    # Find unique name for the file.
    my $i = 1;
    my $base_copy = $base;
    while ($fmgr->exists(File::Spec->catfile($local_path, $base . $ext))) {
        $base = $base_copy . '_' . $i++;
    }

    my $local_relative = File::Spec->catfile($save_path, $base . $ext);
    my $local = File::Spec->catfile($local_path, $base . $ext);
    $fmgr->put_data( $image, $local, 'upload' );

    require MT::Asset;
    my $asset_pkg = MT::Asset->handler_for_file($local);
    return undef if $asset_pkg ne 'MT::Asset::Image';

    my $asset;
    $asset = $asset_pkg->new();
    $asset->file_path($local_relative);
    $asset->file_name($base.$ext);
    my $ext_copy = $ext;
    $ext_copy =~ s/\.//;
    $asset->file_ext($ext_copy);
    $asset->blog_id(0);

    my $original = $asset->clone;
    my $url = $local_relative;
    $url  =~ s!\\!/!g;
    $asset->url($url);
    $asset->image_width($w);
    $asset->image_height($h);
    $asset->mime_type($mimetype);

    $asset->save
        or return undef;

    $asset;
}

1;

__END__
