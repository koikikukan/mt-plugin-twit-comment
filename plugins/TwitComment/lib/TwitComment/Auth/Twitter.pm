package TwitComment::Auth::Twitter;

use strict;

use HTTP::Request::Common;
use LWP::UserAgent;
use Digest::SHA1;
use Net::OAuth;

sub login {
    my $class = shift;
    my ($app) = @_;
    my $q = $app->param;
    my $blog_id = $q->param('blog_id');
    my $static = $q->param('static');

    my $plugin = $app->component("TwitComment");
    my $consumer_key = $plugin->get_config_value('TwitComment_consumerkey', 'blog:' . $blog_id);
    my $consumer_secret = $plugin->get_config_value('TwitComment_consumerkey_secret', 'blog:' . $blog_id);
    my $callback_url = $app->base . $app->mt_path . 'mt-comments.cgi?__mode=oauth_verified&client=twitter&blog_id=' . $blog_id;
    my $request_token_url = 'https://api.twitter.com/oauth/request_token';
    my $request_method = 'GET';

    my $request = Net::OAuth->request("request token")->new(
        consumer_key => $consumer_key,
        consumer_secret => $consumer_secret,
        request_method => $request_method,
        request_url => $request_token_url,
        timestamp => time,
        signature_method => 'HMAC-SHA1',
        nonce => Digest::SHA1::sha1_base64(time . $$ . rand),
        callback => $callback_url,
    );

    $request->sign;
    unless ($request->verify) {
        print('Signature verification failed! check OAuth parameters.');
        return;
    }
    my $ua = LWP::UserAgent->new;
    my $http_hdr = HTTP::Headers->new('Authorization' => $request->to_authorization_header);
    my $http_req = HTTP::Request->new($request_method, $request_token_url, $http_hdr);
    my $res = $ua->request($http_req);

    if ($res->is_success) {
        my $response = Net::OAuth->response('request token')->from_post_body($res->content);
        my $request_token = $response->token;
        my $request_token_secret = $response->token_secret;
        my $authorize_url = 'https://api.twitter.com/oauth/authorize?oauth_token=' . $request_token;

        my $cookie = $app->bake_cookie ( -name=>'TwitComment',
            -value => {
                blog_id => $blog_id,
                static => $static,
                token => $request_token,
                token_secret => $request_token_secret,
            },-path=>'/',
        );
        return $app->redirect($authorize_url,UseMeta => 1, -cookie => $cookie);
    } else {
        my $error_message = $res->as_string;
        return qq(Failed Twitter Authorization.<br />$error_message);
    }
}

1;
