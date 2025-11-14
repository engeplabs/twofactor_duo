<?php

/**
 * @author El-ad Blech <elie@theinfamousblix.com>
 * @author Christoph Wurst <christoph@winzerhof-wurst.at>
 *
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace OCA\TwoFactorDuo\Provider;

use OCA\TwoFactorDuo\DuoUniversal\Client;
use OCA\TwoFactorDuo\DuoUniversal\DuoException;
use OCP\AppFramework\Http\ContentSecurityPolicy;
use OCP\Authentication\TwoFactorAuth\IActivatableByAdmin;
use OCP\Authentication\TwoFactorAuth\IDeactivatableByAdmin;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\IProvidesCustomCSP;
use OCP\Authentication\TwoFactorAuth\IProvidesIcons;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\Template;
use Psr\Log\LoggerInterface;

class DuoProvider implements IProvider, IProvidesCustomCSP, IActivatableByAdmin, IDeactivatableByAdmin, IProvidesIcons {

	/** @var IConfig */
	private $config;

	/** @var ISession */
	private $session;

	/** @var IURLGenerator */
	private $urlGenerator;

	/** @var IRequest */
	private $request;

	/** @var Client */
	private $duoClient;

	/** @var LoggerInterface */
	private $logger;

	/** @var  DuoException */
	private $duoClientInitException;

	/**
	 * Constructor of the DuoProvider.
	 * This als initializes the Duo Client.
	 *
	 * @param IConfig $config
	 * @param ISession $userSession
	 * @param IURLGenerator $urlGenerator
	 * @param IRequest $request
	 * @param LoggerInterface $logger
	 */
	public function __construct(
		IConfig         $config,
		ISession        $userSession,
		IURLGenerator   $urlGenerator,
		IRequest        $request,
		LoggerInterface $logger
	) {
		$this->config = $config;
		$this->session = $userSession;
		$this->urlGenerator = $urlGenerator;
		$this->request = $request;
		$this->logger = $logger;

		// start by getting the config and
		$config = $this->getConfig();
		try {
			$this->duoClient = new Client(
				$config['client_id'],
				$config['client_secret'],
				$config['api_hostname'],
				$config['redirect_uri']
			);
		} catch (DuoException $e) {
			$logger->error('Could not initialize Duo Client.', [$e]);
			// can't do anything here -> store and evaluate later
			$this->duoClientInitException = $e;
		}
	}

	/**
	 * Get unique identifier of this 2FA provider
	 *
	 * @return string
	 */
	public function getId(): string {
		return 'duo';
	}

	/**
	 * Get the display name for selecting the 2FA provider
	 *
	 * @return string
	 */
	public function getDisplayName(): string {
		return 'Duo';
	}

	/**
	 * Get the description for selecting the 2FA provider
	 *
	 * @return string
	 */
	public function getDescription(): string {
		return 'Uses Cisco Duo for 2FA';
	}

	/**
	 * Returns the path to the light icon.
	 *
	 * @return string
	 */
	public function getLightIcon(): string {
		return image_path('twofactor_duo', 'duo_icon.png');
	}

	/**
	 * Returns the path to the dark icon.
	 * In this implementation, it's the same as the light icon. Sorry. :)
	 *
	 * @return string
	 */
	public function getDarkIcon(): string {
		return $this->getLightIcon();
	}

	/**
	 * Generates and returns the required CSPs for the inline scripts of this
	 * provider.
	 *
	 * @return ContentSecurityPolicy the generated CSP
	 */
	public function getCSP(): ContentSecurityPolicy {
		$csp = new ContentSecurityPolicy();
		// scripts that can be stored inside the session
		$possibleScripts = ['redirect_script', 'complete_script'];
		foreach ($possibleScripts as $script) {
			// check if session contains script
			if ($this->session->exists($script)) {
				// if so, obtain the script and immediately remove it from the session
				$scriptContent = $this->session->get($script);
				$this->session->remove($script);
				// calculate script CSP and add it
				$csp->addAllowedScriptDomain($this->calculateScriptCSP($scriptContent));
			}
		}
		return $csp;
	}

	/**
	 * Get the template for rending the 2FA provider view. Depending on the presence
	 * of get parameters and session state this has function returns different
	 * templates.
	 *
	 * @param IUser $user the user which is currently accessing the site
	 * @return Template the template which should be shown
	 */
	public function getTemplate(IUser $user): Template {
		// in case the login flow is used to authenticate a client app, we need to store the redirect URL inside the
		// session to redirect back to it after successful duo flow.
		$redirectUrlAfterSuccess = $this->request->getParam('redirect_url');
		if ($redirectUrlAfterSuccess != null) {
			$this->session->set('redirect_url_after_success', $redirectUrlAfterSuccess);
		}

		// Duo uses the error GET parameter to report back errors
		// with error, error_description is also set
		if ($this->request->getParam('error') != null) {
			$this->logger->warning('Possible error from Duo 2FA.',
				[$this->request->getParam('error'), $this->request->getParam('error_description')]);
			return $this->showErrorPage(
				$this->request->getParam('error') . ': ' .
				$this->request->getParam('error_description')
			);
		}
		// check if we are trying to finish up by checking if we have both
		// the state and duo_code GET parameter set inside the URL
		if ($this->request->getParam('state') != null &&
			$this->request->getParam('duo_code') != null) {
			// if both GET parameters are set, but we have no stored state inside
			// the session, cancel and show the error page
			if (!$this->session->exists('state')) {
				$this->logger->warning('User submitted state and duo_code but there was no state in session.',
					[$this->request->getParam('state'), $this->request->getParam('duo_code')]);
				return $this->showErrorPage(
					'No active login process found. Please try again.');
			}
			// if we have a stored state, get it and immediately delete it afterward
			// since now it's been consumed.
			$storedState = $this->session->get('state');
			$this->session->remove('state');
			// if the stored state does not match the GET param state, show the
			// error page
			if ($storedState != $this->request->getParam('state')) {
				$this->logger->warning('User submitted state and duo_code but state did not match state in session.',
					[$this->request->getParam('state'), $this->request->getParam('duo_code')]);
				return $this->showErrorPage('Duo state does not match saved state.');
			}
			// we have the correct state and the duo code - complete the login process
			return $this->completeLoginProcess($user, $this->request->getParam('duo_code'));
		}
		// we do not have the state nor duo_code, so we are at the beginning
		// of the flow - start the login process
		return $this->startLoginProcess($user);
	}

	/**
	 * Verify the given challenge
	 *
	 * @param IUser $user the user which is currently accessing the site
	 * @param string $challenge the challenge (complete token) that the user submitted
	 * @return bool whether the user passed the challenge
	 */
	public function verifyChallenge(IUser $user, string $challenge): bool {
		$completeToken = $this->session->get('duo_challenge_complete_token');
		// always remove complete token here
		$this->session->remove('duo_challenge_complete_token');
		if ($completeToken == $challenge) {
			return true;
		} else {
			$this->logger->warning('User submitted invalid challenge for Duo 2FA.', [$user, $challenge]);
		}
		return false;
	}

	/**
	 * Decides whether 2FA is enabled for the given user
	 *
	 * @param IUser $user
	 * @return boolean
	 */
	public function isTwoFactorAuthEnabledForUser(IUser $user): bool {
		return true;
	}

	/**
	 * Disable this provider for the given user.
	 *
	 * @param IUser $user the user to deactivate this provider for
	 *
	 * @return void
	 *
	 * @since 15.0.0
	 */
	public function disableFor(IUser $user): bool {
		return true;
	}

	/**
	 * Enable this provider for the given user.
	 *
	 * @param IUser $user the user to activate this provider for
	 *
	 * @return void
	 *
	 * @since 15.0.0
	 */
	public function enableFor(IUser $user): bool {
		return true;
	}

	/**
	 * Here we start the login process which begins by forwarding the user to Duo.
	 *
	 * @param IUser $user the user which is currently accessing the site
	 * @return Template the challenge template with its data
	 */
	private function startLoginProcess(IUser $user): Template {
		// first we need to check if the Duo Client could be properly initialized
		if ($this->duoClientInitException != null) {
			return $this->showErrorPage('Error while initializing Duo Client.');
		}
		// then we perform health check on the Duo Client
		try {
			$this->duoClient->healthCheck();
		} catch (DuoException $e) {
			$msg = 'Duo Client health check failed';
			$this->logger->error($msg, [$e]);
			// TODO add config to set if we want to fail open
			return $this->showErrorPage($msg);
		}
		// generate and store the state and then create the auth URL
		$state = $this->duoClient->generateState();
		$this->session->set('state', $state);
		try {
			$prompt_uri = $this->duoClient->createAuthUrl($user->getUID(), $state);
		} catch (DuoException $e) {
			$msg = 'Duo auth URL could not be created.';
			$this->logger->error($msg, [$e]);
			return $this->showErrorPage($msg);
		}
		// prepare redirect script for template
		$redirectScript = 'window.location.href = \'' . $prompt_uri . '\';';
		$this->session->set('redirect_script', $redirectScript);

		$tmpl = new Template('twofactor_duo', 'challenge');
		$tmpl->assign('prompt_uri', $prompt_uri);
		$tmpl->assign('redirect_script', $redirectScript);
		return $tmpl;
	}

	/**
	 * After we got redirected from Duo, we need to validate the duo_code and
	 * complete the login process.
	 *
	 * @param IUser $user the user which is currently accessing the site
	 * @param string $duo_code the code obtained from Duo
	 * @return Template the complete template with its data
	 */
	private function completeLoginProcess(IUser $user, string $duo_code): Template {
		// first we need to check if the Duo Client could be properly initialized
		if ($this->duoClientInitException != null) {
			return $this->showErrorPage('Error while initializing Duo Client.');
		}
		// if so, we check validate the duo_code
		try {
			$this->duoClient->exchangeAuthorizationCodeFor2FAResult($duo_code, $user->getUID());
		} catch (DuoException $e) {
			// if there was an error during, to code was either incorrect or there might
			// be a discrepancy with the system clock - show the error page
			$msg = 'Error decoding Duo result. Confirm device clock is correct.';
			$this->logger->error($msg, [$e]);
			return $this->showErrorPage($msg);
		}
		// prepare session for validation step
		$token = bin2hex(openssl_random_pseudo_bytes(32));;
		$this->session->set('duo_challenge_complete_token', $token);
		$completeScript = 'document.getElementById(\'complete-form\').submit();';
		$this->session->set('complete_script', $completeScript);

		$config = $this->getConfig();
		// if the flow was started with a specific redirect URL we need to add it to our URL where the Duo-challenge is
		// completed (stored in "redirect_uri" config)
		$redirectUri = $this->session->exists('redirect_url_after_success') ?
			$config['redirect_uri'] . '?redirect_url=' . urlencode($this->session->get('redirect_url_after_success')) :
			$config['redirect_uri'];
		// make sure that the redirect_url_after_success is deleted
		$this->session->remove('redirect_url_after_success');

		$tmpl = new Template('twofactor_duo', 'complete');
		$tmpl->assign('complete_token', $token);
		$tmpl->assign('redirect_uri', $redirectUri);
		$tmpl->assign('complete_script', $completeScript);
		return $tmpl;
	}

	/**
	 * If anything goes wrong during the 2FA flow with Duo, return the template
	 * returned by this function.
	 * The template contains the given error message as well as a button to restart
	 * the 2FA process.
	 *
	 * Besides returning the template which shows the error, this also cleans up
	 * any remaining state from the current login attempt.
	 *
	 * @param string $error_message the error message, which will be displayed to the user
	 * @return Template the error template with its data
	 */
	private function showErrorPage(string $error_message): Template {
		// always remove current state on error
		$this->session->remove('state');
		// since there could be a stored redirect_url_after_success, we need to remove it as well
		$this->session->remove('redirect_url_after_success');

		$config = $this->getConfig();
		$tmpl = new Template('twofactor_duo', 'error');
		$tmpl->assign('error_message', htmlspecialchars($error_message));
		$tmpl->assign('redirect_uri', $config['redirect_uri']);
		return $tmpl;
	}

	/**
	 * Retrieves the config values for the twofactor_duo provider app.
	 *
	 * @return mixed the config set under twofactor_duo
	 */
	private function getConfig(): mixed {
		return $this->config->getSystemValue('twofactor_duo', null);
	}

	/**
	 * This method calculates the CSP for the script given as the $scriptContent
	 * so that it can be added to the site as an inline script without violating
	 * the CSP.
	 *
	 * @param string $scriptContent the exact script that will be added as an inline script
	 * @return string the CSP header that should be added to the allowed script domains
	 */
	private function calculateScriptCSP(string $scriptContent): string {
		// generate and encode the SHA-256 hash of the script content
		$hash = hash('sha256', $scriptContent, true);
		$base64Hash = base64_encode($hash);
		// generate the CSP header with the hash
		return '\'self\' \'sha256-' . $base64Hash . '\'';
	}
}
