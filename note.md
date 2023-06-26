# Upgrade to Symfony 6
## Update '_composer.json_'



## [ Chapter 13 - Custom Authenticator authenticate() ]

For LoginFormAuthenticator.php,

* Step 1,\
In old system,\
&emsp;we used getCredentials() to get userCredentials\
&emsp;&emsp;&emsp;used getUser() to get an user using the credentials\
&emsp;&emsp;&emsp;used checkCredentials() to check whether the password matching as follows:
```
    public function getCredentials(Request $request)
    {
        $credentials = [
            'email' => $request->request->get('email'),
            'password' => $request->request->get('password'),
            'csrf_token' => $request->request->get('_csrf_token'),
        ];
        $this->session->set(
            Security::LAST_USERNAME,
            $credentials['email']
        );

        return $credentials;
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $token = new CsrfToken('authenticate', $credentials['csrf_token']);
        if (!$this->csrfTokenManager->isTokenValid($token)) {
            throw new InvalidCsrfTokenException();
        }

        $user = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $credentials['email']]);

        if (!$user) {
            throw new UserNotFoundException('Email could not be found.');
        }

        return $user;
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return $this->passwordHasher->isPasswordValid($user, $credentials['password']);
    }
```
In new system,\
&emsp;authenticate() does everything above for us:
```
    public function authenticate(Request $request): Passport
    {
        $email = $request->request->get('email');
        $password = $request->request->get('password');
        
        return new Passport(
                    new UserBadge(
                        $email,
                        function ($userIdentifier) {
                            $user = $this->entityManager
                                            ->getRepository(User::class)
                                            ->findOneBy(['email' => $userIdentifier]);
                            if (!$user) {
                                throw new UserNotFoundException();
                            }

                            return $user;
                        }
                    ),
                    new PasswordCredentials($password),
                    [
                        new CsrfTokenBadge('authenticate', $request->request->get('_csrf_token')),
                        (new RememberMeBadge())->enable()
                    ]
                );
    }
```
1. '_UserBadge_' accepts an userIdentifier as a first argument and find an user using the app_user_provider specified in '_security.yaml_'.\
```
In security.yaml:
    providers:
        # used to reload user from session & other features (e.g. switch_user)
        app_user_provider:
            entity:
                class: App\Entity\User
                property: email
```
&emsp;&emsp;&emsp;Otherwise, we can explicitly finding it by ourselves by passing a function doing it as the second argument as follows:
```
    new UserBadge(
        $email,
        function ($userIdentifier) { // $userIdentifier is the first argument.
            $user = $this->entityManager
                            ->getRepository(User::class)
                            ->findOneBy(['email' => $userIdentifier]);
            if (!$user) {
                throw new UserNotFoundException();
            }

            return $user;
        }
    ),
```
2. As the second parameter, '_PasswordCredentials_' will accept a password and check whether the password matches with the found user's password or not.

3. As the third parameter, we can pass an array and we pass '_CsrfTokenBadge_' which is to use CsrfToken to authenticate. first string type parameter of the badge is to identify what type of csrfToken it is and the second parameter is to grab an actual cstfToken from the input in Login page(login.html.twig).
```
In login.html.twig,
...
    <input type="hidden" name="_csrf_token"
            value="{{ csrf_token('authenticate') }}"
    >
...
```

* Step 2,\
the rest, refer to [here](https://symfonycasts.com/screencast/symfony6-upgrade/custom-authenticator#play)



## [ Chapter 14 - Password encoders -> password_hashers & debug:firewall ]
1. In '_security.yaml_' :\
replace the following:
```
    encoders: // 'password_hashers' will do the job now instead.
        App\Entity\User:
            algorithm: auto // it tells the system to use 'auto' algorithm to encode password.
```
&emsp;&emsp;&emsp;with the following:
```
    # https://symfony.com/doc/current/security.html#registering-the-user-hashing-passwords
    password_hashers:
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface: 'auto'
```

* '_php bin/console debug:firewall_':\
The above command shows us the deatils of our authentication logic.

## [ Chapter 15 - Hunt down remaining deprecation warnings ]
* 'ROLE_PREVIOUS_ADMIN' => 'IS_IMPERSONATOR'
* 'IS_AUTHENTICATED_ANONYMOUSLY' => 'PUBLIC_ACCESS'
* stop using '_SessionInterface $session_', instead grab session from request right away as follows:
```
Instead of,
    $this->session
Use
    $request->getSession() // Request $request
```
* use '_EntityManagerInterface_' to get entityManager instead of 'getDoctrine()->getManager()'

* '_tail -f var/log/dev.log | grep deprecation_' will monitor any deprecation messages.
* for checking any missed deprecation warnings, we can simply log it using monolog bundle with configuration in
'_monolog.yaml_' as follows:
```
when@prod:
    monolog:
        handlers:
            main:
                type: fingers_crossed
                action_level: error
                handler: nested
                excluded_http_codes: [404, 405]
                buffer_size: 50 # How many messages should be saved? Prevent memory leaks
            nested:
                type: stream
                path: php://stderr
                level: debug
                formatter: monolog.formatter.json
            console:
                type: console
                process_psr_3_messages: false
                channels: ["!event", "!doctrine"]
            deprecation:
                type: stream
                channels: [deprecation]
                path: php://stderr // deprecation message will be recorded here.
                # path: "%kernel.logs_dir%/%kernel.environment%.deprecations.log"
```
* useful technique: try using '_\[rootPath\]/\_profiler_' to check any residual deprecations

## [ Chapter 16 - Upgrading to Symfony 6.0 ]
[ Rector Upgrades to 6.0 ]
- Go to 'rectorphp/rector-symfony' git repo and copy & paste the symfony config info onto '_rector.php_' as such:
```
    $rectorConfig->sets([
        SymfonyLevelSetList::UP_TO_SYMFONY_60,
        SymfonySetList::SYMFONY_CODE_QUALITY,
        SymfonySetList::SYMFONY_CONSTRUCTOR_INJECTION,
    ]);
```
- run '_vendor/bin/rector process src_'

[ Upgrade via Composer ]
- Upgrade Symfony related package versions in '_composer.json_' like '5.4.\*' to '6.0.\*'
- run '_composer up_'
    - if there is any compatibility error, then try running '_composer outdated_' to see if there is any available updated versions for packages which can potentially be compatible with Symfony 6.0
- update the versions of pacakages to the compatible ones in composer.json
- run '_composer up_' again.
- run '_composer outdated_' again just in case there is any residual updatable packages left or not.

## [ Chapter 17 - Final upgrades & cleanups ]
