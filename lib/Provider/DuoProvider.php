<?php
namespace OCA\TwoFactorDuo\Provider;

use OCA\TwoFactorDuo\Web;
use OCP\AppFramework\Http\ContentSecurityPolicy;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\IProvidesCustomCSP;
use OCP\IConfig;
use OCP\IUser;
use OCP\Template;

class DuoProvider implements IProvider, IProvidesCustomCSP {
	private $config;
	private function getConfig() {
		return $this->config->getSystemValue('twofactor_duo', null);
	}
	public function __construct(IConfig $config) {
		$this->config = $config;
	}
	public function getId(): string {
		return 'duo';
	}
	public function getDisplayName(): string {
		return 'SFAI Duo Security 2FA';
	}
	public function getDescription(): string {
		return 'SFAI Duo Security 2FA';
	}
	public function getCSP(): ContentSecurityPolicy {
		$csp = new ContentSecurityPolicy();
		$csp->addAllowedChildSrcDomain('https://*.duosecurity.com');
		$csp->addAllowedStyleDomain('https://*.duosecurity.com');
		$csp->addAllowedFrameDomain('https://*.duosecurity.com');
		return $csp;
	}
	public function getTemplate(IUser $user): Template {
		$config = $this->getConfig();
		$tmpl = new Template('twofactor_duo', 'challenge');
		$tmpl->assign('user', $user->getUID());
		$tmpl->assign('IKEY', $config['IKEY']);
		$tmpl->assign('SKEY', $config['SKEY']);
		$tmpl->assign('HOST', $config['HOST']);
		$tmpl->assign('CALL', $config['CALL']);
		return $tmpl;
	}
	public function verifyChallenge(IUser $user, $challenge): bool {
		$config = $this->getConfig();
		$web = new Web($config['IKEY'], $config['SKEY'], $config['HOST'], $config['CALL']);
		$duo_res = $web->decode($_GET['duo_code'], $user->getUID());
		
		if($duo_res['auth_result']['result'] == 'allow') return true;
		else return false;
	}
	public function isTwoFactorAuthEnabledForUser(IUser $user): bool {
		return true;
	}
}
