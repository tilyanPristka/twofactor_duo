<?php
use OCA\TwoFactorDuo\Web;

$web = new Web($_['IKEY'], $_['SKEY'], $_['HOST'], $_['CALL']);
$sig_request = $web->duo_auth($_['user']);