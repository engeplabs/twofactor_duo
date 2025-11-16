# twofactor_duo

This plugin enables Duo two-factor authentication for Nextcloud. It has been tested to work with Nextcloud 29.X and
updated to be compatible with the new Duo Universal Prompt (Duo Web SDK 4).

## Warning

This is an experimental plugin. It requires additional testing, and we are not taking any responsibility for its use.
Use it at your own risk.

## Configuration

Add your duo configuration to your Nextcloud's `config/config.php` file:

```
  'twofactor_duo' => [
    'client_id' => 'xxx',
    'client_secret' => 'yyy',
    'api_hostname' => 'api.host.from.duo',
    'redirect_uri' => 'https://nextcloud.local/index.php/login/challenge/duo',
  ],
```

Make sure that the redirect_uri matches the URL under which the Duo challenge is accessed.
