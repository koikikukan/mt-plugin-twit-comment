<?php
require_once('commenter_auth_lib.php');

class TwitCommenterAuth extends BaseCommenterAuthProvider {
    function get_key() {
        return 'TwitComment';
    }
    function get_label() {
        return 'Twitter Commenter Authenticator';
    }
    function get_logo() {
        return 'plugins/TwitComment/images/twitter_logo.png';
    }
    function get_logo_small() {
        return 'plugins/TwitComment/images/signin_twitter_small.png';
    }
}

global $_commenter_auths;
$provider = new TwitCommenterAuth();
$_commenter_auths[$provider->get_key()] = $provider;

?>
