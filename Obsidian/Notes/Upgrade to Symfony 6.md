## Upgrade to Symfony 5.4 
### 1. Update '_composer.json_'
* update versions of packages
			- find packages starting with "symfony/" and update their versions up to '5.4.*'
				(except for the ones which have their own versioning)
```json
    "extra": {
        "symfony": {
            "allow-contrib": false,
            // performance optimization from "symfony/flex"
            // only considers packages matching the specified version
            "require": "5.4.*"
        }
    }
```
- run '_composer up \['symfony\/\*'\] \[-w\]_'
	*  -w is to ask composer to update all related dependencies as well


### 2. Apply updated symfony rules to codebase with 'Rector'
* install rector via '_composer require rector\/rector --dev_'
(can also be checked from rector github repo)
* creates '_rector.php_' config file outside '_/vendor_'
(can get the code from [rector-symfony](https://github.com/rectorphp/rector-symfony/tree/main) repo)
```php
use Rector\Symfony\Set\SymfonySetList;
use Rector\Config\RectorConfig;

return static function (RectorConfig $rectorConfig): void {
    $rectorConfig->symfonyContainerXml(__DIR__ . '/var/cache/dev/App_KernelDevDebugContainer.xml');

    $rectorConfig->sets([
	    // includes all the rules up until 5.4
        SymfonyLevelSetList::UP_TO_SYMFONY_54,
        SymfonySetList::SYMFONY_CODE_QUALITY,
        SymfonySetList::SYMFONY_CONSTRUCTOR_INJECTION,
    ]);
};
```
* run '_vendor/bin/rector process src_' for rector to update & refactor codebase
(It still does not resolve component path gracefully via not using 'use' keyword properly)


### 3. Fix coding style after Rector with 'Php-cs-fixer'
* '_mkdir -p tools/php-cs-fixer_' && '_composer require --working-dir=tools/php-cs-fixer friendsofphp/php-cs-fixer_'
(We just need a standalone php-cs-fixer binary file and don't want any potential problems from incompatibility with other packages, so we create it in the seperate directory.)
* add '_.php-cs-fixer.cache_' in '_/tools/php-cs-fixer/vendor/_'
* create a config file '_.php-cs-fixer.php_' under the project directory
(copy and paste the source code onto the config file from [symfonycast](https://symfonycasts.com/screencast/symfony6-upgrade/rector-fixup))
```php
<?php

$finder = PhpCsFixer\Finder::create()
	->in(__DIR__.'/src')
;

$config = new PhpCsFixer\Config();
return $config->setRules([
        '@Symfony' => true,
        'yoda_style' => false,
    ])
    ->setFinder($finder)
;
```
* run '_tools/php-cs-fixer/vendor/bin/php-cs-fixer fix_'
* remove '_configureRouting()_' in '_Kernel.php_' since it's already in "_use MicroKernelTrait_;"


### 4. Update Recipes
(Recipe usually comes with package and it does add config file or modify certain files like '.env')
* run '_composer recipes:update_'
(added by 'Symfony Flex' and it checks installed recipes and looks for newer ones )
* run '_git status_' or '_git diff --cached \[filename\]_' to check any changes and resolve any conflicts

###### \[ FrameworkBundle \] refers to [here](https://symfonycasts.com/screencast/symfony6-upgrade/framework-bundle-recipe)
* '_git status_' will show the following:
![[Pasted image 20230626142440.png]]
(Briefly explaining of what happened, '_bootstrap.php_' which is for reading and setting up the environment variables is now delegated to '_/vendor/autoload\_runtime.php_'(Symfony runtime component) in '_public/index.php_')
* '_/vendor/autoload\_runtime.php_' requires symfony runtime package, run '_composer require symfony/runtime_'
* remove everything in '_Kernel()_' in '_Kernel.php_' since now all in '_MicroKernelTrait_'
###### \[ Symfony/console, Symfony/twig-bundle, doctrine/doctrine-bundle \] refers to [here](https://symfonycasts.com/screencast/symfony6-upgrade/upgrade-recipes)
###### \[ Symfony/debug-bundle, monolog-bundle, routing, security-bundle, translation, validator, web-profiler-bundle \] refers to [here](https://symfonycasts.com/screencast/symfony6-upgrade/upgrade-recipes2)
* For '_Symfony/monolog-bundle_' conflicts:
```yaml
monolog:
    channels:
        - markdown
        - deprecation # Deprecations are logged in the dedicated "deprecation" channel when it exists
```

* For '_Symfony/security-bundle_' conflicts:
```yaml
	enable_authenticator_manager: true # enables a new security system
	# replace 'encoders' tag with 'password_hashers' tag
	password_hashers:
		# uses 'auto' algorithm for hashing the password
		Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface: 'auto'
	
	...
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            lazy: true
            provider: app_user_provider
            guard:
                authenticators:
                    - App\Security\LoginFormAuthenticator
            logout:
                path: app_logout
    ...
```

###### \[ Symfony/webpack-encore-bundle, monolog-bundle, routing, security-bundle, translation, validator, web-profiler-bundle \] refers to [here](https://symfonycasts.com/screencast/symfony6-upgrade/encore-upgrade)
* For '_Symfony/webpack-encore-bundle', change '_stimulus_' to '_@hotwired/stimulus_'.
(mainly in '_assets/controllers/*\_controller.js_' files)

### 5. Upgrade to PHP 8
###### \[ Update to PHP8 new syntax \]
* config '_rector.php_' as follows:
```php
<?php

use Rector\Symfony\Set\SymfonyLevelSetList;
use Rector\Symfony\Set\SymfonySetList;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Config\RectorConfig;

return static function (RectorConfig $rectorConfig): void {
    $rectorConfig->symfonyContainerXml(__DIR__ . '/var/cache/dev/App_KernelDevDebugContainer.xml');
  
    $rectorConfig->sets([
	    // upgrade up until php8.0
        $rectorConfig->sets([LevelSetList::UP_TO_PHP_80])
    ]);
};
```
* run '_vendor/bin/rector process src_'
(introduces sth new like "Promoted properties" etc. For more details, refer to [here](https://getrector.com/blog/smooth-upgrade-to-php-8-in-diffs))
* update '_composer.json_'
```json
...
 "require": {
	...
	"php": "^8.0.0",
	...
	"symfony/flex": "^2.1.*", // requires php8
	...
	 "config": {
        ...
        "platform": {
	        "php": "8.0.2" // install packages compatible with php8.0.2
        },
        ...
	},
	...
 }
```
* run '_composer up_'
###### \[ Annotations -> Attibutes \]
* use [annotations instead of attributes](https://getrector.com/blog/how-to-upgrade-annotations-to-attributes) via updating '_rector.php_' config file.
```php
<?php
use Rector\Doctrine\Set\DoctrineSetList;
use Rector\Symfony\Set\SymfonySetList;
use Rector\Symfony\Set\SensiolabsSetList;
use Rector\Config\RectorConfig;

return function (RectorConfig $rectorConfig): void {
    $rectorConfig->sets([
        DoctrineSetList::ANNOTATIONS_TO_ATTRIBUTES,
        SymfonySetList::ANNOTATIONS_TO_ATTRIBUTES,
        SensiolabsSetList::FRAMEWORK_EXTRA_61,
    ]);
```
* run '_vendor/bin/rector process_'
* change '_php-cs-fixer_' again as follows:
```php
In '.php-cs-fixer.php',

<?php

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__.'/src')
;
$config = new PhpCsFixer\Config();

return $config->setRules([
        '@Symfony' => true,
        'yoda_style' => false,
        'class_attributes_separation' => [
            'elements' => [
                'method' => 'one', // add one more line break after method
                'property' => 'one', // add one more line break after method
                'trait_import' => 'one', // add one more line break after use Trait;
            ]
        ]
    ])
    ->setFinder($finder)
;
```

* run '_tools/php-cs-fixer/vendor/bin/php-cs-fixer fix_'

###### \[ Add property types to Entities \]
* run '_symfony console doctrine:schema:update --dump-sql_'
(makes database in sync with 'doctrine entity metadata')
* add '?\[type\]' to each property of entities
```php
private ?int $id = null
```
* remove '#\[ORM\...(targetEntity: ~:class)]' since Doctrine now can guess its property by itself
before:
```php
    #[ORM\ManyToOne(targetEntity: Question::class, inversedBy: 'answers')]
    #[ORM\JoinColumn(nullable: false)]
    private ?\App\Entity\Question $question = null;
```
after:
```php
    #[ORM\ManyToOne(inversedBy: 'answers')]
    #[ORM\JoinColumn(nullable: false)]
    private ?Question $question = null;
```
* run '_symfony console doctrine:schema:update --dump-sql_' to make sure everything works fine.
* If there is anything using '_Gedmo_', Rector has not updated so has to change it to attributes by ourselves.
```php
	#[Gedmo\Slug(fields: "name")]
	#[ORM\Column(type: 'string', length: 100, unique: true)]
    private ?string $slug = null;
```
###### \[ Security Upgrades \] refers to [here](https://symfonycasts.com/screencast/symfony6-upgrade/authenticator-upgrade)
* add '_PasswordAuthenticatedUserInterface_' to anywhere implements '_UserInterface_' 
('_getPassword()_' is now removed from '_UserInterface_' and delegated to '_PasswordAuthenticatedUserInterface_') 
* replace '_getUsername()_' of '_UserInterface_' with '_getUserIdentifier()_'
* update '_security.yaml_' if not updated yet as follows:
```yaml
security:
	...
	# updates the old 'guard' authenticator to the new 'custom' authenticator
    enable_authenticator_manager: true
    ...
```
* update '_Security/LoginFormAuthenticator.php_'
	*  replace '_AbstractFormLoginAuthenticator_' with '_AbstractLoginFormAuthenticator_'
	*  remove '_PasswordAuthenticatedInterface_'
	*  remove '_supports()_' which is now in '_AbstractClass_'
	*  use ?Response as a return type for both '_onAuthenticationSuccess()_' and '_onAuthenticationFailure()_'
```php
# before
class LoginFormAuthenticator extends AbstractFormLoginAuthenticator implements PasswordAuthenticatedInterface
...
    protected function getLoginUrl(): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }
...
# after 
class LoginFormAuthenticator extends AbstractLoginFormAuthenticator
...
    // public function supports(Request $request)
    //{
    //    return self::LOGIN_ROUTE === $request->attributes->get('_route')
    //        && $request->isMethod('POST');
    //}
...
public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
...
public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
...
    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }
```
*  update Custom Authenticator '_authenticate()_' in '_LoginFormAuthenticator.php_' as follows:
1.
In old system,
		we used getCredentials() to get userCredentials
			used getUser() to get an user using the credentials
			used checkCredentials() to check whether the password matching as follows:
```php
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

In new system,
	authenticate() does everything above for us:
```php
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
'_UserBadge_' accepts an 'userIdentifier' as a first argument and find an user using the 'app_user_provider' specified in '_security.yaml_'.

```
In security.yaml:
    providers:
        # used to reload user from session & other features (e.g. switch_user)
        app_user_provider:
            entity:
                class: App\Entity\User
                property: email
```

Otherwise, we can explicitly finding it by ourselves by passing a function doing it as the second argument as follows:

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