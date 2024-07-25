<img src="https://1.tilyanpristka.id/images/tP-logo-rounded.png" height="70" align="right">

# 2FA <img src="https://upload.wikimedia.org/wikipedia/commons/8/8b/Duo_Logo_Green.svg" height="30"> DUO for <img src="https://upload.wikimedia.org/wikipedia/commons/6/60/Nextcloud_Logo.svg" height="40"> Nextcloud Any Versions

Experimental New Method Two-Factor DUO Universal Prompt for Nextcloud
>Tested on Nextcloud versions 27, 28, and 29
## Configuration
Add your duo configuration to your Nextcloud's `nextcloud/config/config.php` fils:
```
'twofactor_duo' => [
    'IKEY' => 'xxx',
    'SKEY' => 'yyy',
    'HOST' => '*.duosecurity.com',
    'CALL' => 'https://example.com/login/callback/duo',
  ],
```
## Nextcloud Lib Patch
`nextcloud/lib/public/Authentication/TwoFactorAuth/IProvider.php`

`nextcloud/lib/private/Authentication/TwoFactorAuth/Manager.php`

`nextcloud/apps/twofactor_backupcodes/lib/Provider/BackupCodesProvider.php`
```
public function verifyChallenge(IUser $user, string $challenge): bool;
```
Change to: (remove the word `string`)
```
public function verifyChallenge(IUser $user, $challenge): bool;
```
## Nextcloud Core Patch
`nextcloud/core/routes.php`
```
['name' => 'TwoFactorChallenge#solveChallenge', 'url' => '/login/challenge/{challengeProviderId}', 'verb' => 'POST'],
```
After that line, add this:
```
['name' => 'TwoFactorChallenge#solveChallenge', 'url' => '/login/callback/{challengeProviderId}', 'verb' => 'GET'],
```

## Please come to our website https://tilyanpristka.id/en/
