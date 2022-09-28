# PSR-7/PSR-15 Sessions 

## Problems

1. Currently PHP sessions are not compatible with `PSR-7`
2. The session object is widely used, but there is no standard. A session spec would actually help solve a number of problems, including:
    - Standardizing between frameworks
    - Using other people's implementations easily
    - Swapping out types of implementations so if you want to use Swoole, you can move away from the PHP sessions and switch to a Redis handler
    - Lots of companies like to move their controller logic into reusable services which would be much easier with a session spec.
    - Improved integration testing
3. Another important part of this PSR, I believe, is for a standard way to set and get the Session object on the `ServerRequestInterface` object, without this feature, I think it would be incomplete.

## Security

- Security is an issue and a potential complexity. I believe by also standardizing the hooks into the session lifecycle, such as `startup` and `shutdown` this will bring enough flexibility into the session spec, so developers are able to deal with security related issues such as validating the session ID perhaps or deleting previous data etc.
- Take into consideration OWASP recommendations, making all compliant session libraries more secure, including:
    - the default session ID name to be `id` to prevent `Session ID Name Fingerprinting`
    - the session ID should be at least 128 bits (16 bytes)
    - regenerating the session ID after any changes to the user privilege level in the session
    - and other recommendations such as cookie settings etc.

## Objectives

- User can set, get, check, clear or destroy sessions completely
- Middleware needs to start, close sessions, set the id, and get the id once the storage creates the ID or regenerates the ID so that it can write to the cookie
- Middleware also needs to know if the session was destroyed so it can delete the cookie, if cookies are used.
- Hooks into the session lifecycle for security purposes, needs to be handled
- It needs to work with various types of storage, e.g PHP Sessions, Redis, JWT tokens and single long-running processes e.g. Swoole.

## Initial Concept

```php
interface SessionInterface
{
    public function set(string $key, $value) : void;

    public function get(string $key, $default = null);

    public function unset(string $key): void;

    public function has(string $key): bool;

    public function clear(): void;

    public function destroy(): void;

    public function start(?string $sessionId): bool;

    public function close(): bool;

    /**
     * Get the session Id, null means session was destroyed (or not started).
     */
    public function getId(): ?string;

    /**
     * Replace the current session ID with a new one, this should be called once the user authenticaticates  
     * (or any changes to privilege level - OWASP recommendation)
     */
    public function regenerateId(): bool;
}
```

With regards to standardizing the setting and getting the session object on `ServerRequestInterface` object, this is important since there needs to be a standard way to get the session object from the middleware and users would benefit from a standard way to get this object as well.

```php
interface ServerRequestSessionInterface 
{
    public function setSession(SessionInterface $session): void;
    public function getSession(): SessionInterface;
}
```

I am not sure about the naming though if this interface is used, but i think we should use similar naming conventions to other PSRs. 
Hopefully using an interface will allow to extend current PSRs and not break anything. A potential issue that needs to be considered is, if the session was not added, do you throw an exception, start a session or return `null` etc?

## Example Middleware

```php
class SessionMiddleware implements MiddlewareInterface
{
    private SessionInterface $session;
    private string $cookieName = 'id';
    private int $timeout = 900; // 15 minutes
    private string $sameSite = 'lax';
    private string $cookiePath = '/';

    public function __construct(SessionInterface $session)
    {
        $this->session = $session;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $sessionId = $this->getSessionId($request); // Get value from cookie, session id or perhaps JWT token?

        $this->session->start($sessionId);

        $response = $handler->handle($request->withAttribute('session', $this->session));

        $this->session->close(); // close session if still open, user may have destroyed or closed manually

        return $this->addCookieToResponse($request, $response);
    }

    /**
     * If the session was destroyed, there will be no id, so delete delete delete. If the session ID was regenerated, then
     * the cookie needs to be updated.
     */
    private function addCookieToResponse(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $cookieValue = $this->session->getId() == '';
        $cookieExpires = $cookieValue ? 1 : time() + $this->timeout;

        return $response->withAddedHeader(
             'Set-Cookie', $this->createCookieString($cookieValue, $cookieExpires, $request)
         );
    }

    private function getSessionId(ServerRequestInterface $request): ?string
    {
        $cookies = $request->getCookieParams();

        return $cookies[$this->cookieName] ?? null;
    }

    private function createCookieString(string $sessionId, int $expires, ServerRequestInterface $request): string
    {
        return sprintf(
            '%s=%s; expires=%s; path=%s; samesite=%s;%s httponly',
            $this->cookieName,
            $sessionId,
            gmdate(\DateTime::COOKIE, $expires),
            $this->cookiePath,
            $this->sameSite,
            $request->getUri()->getScheme() === 'https' ? ' secure;' : null
        ) ;
    }
}
```

Here is a simple example to demonstrate the concept

```php
class PhpSession implements SessionInterface
{
    private ?string $id = null;
    private array $session = [];
    private bool $isRegenerated = false;
    private bool $isStarted = false;

    public function start(?string $id): bool
    {
        if ($this->isStarted) {
            return false;
        }

        $this->id = $id ?: $this->generateId();

        session_id($this->id);

        // Disable the PHP cookie features, credit to @pmjones for this
        $this->isStarted = session_start([
            'use_cookies' => false,
            'use_only_cookies' => false,
            'use_trans_sid' => false
        ]);

        $this->session = $_SESSION ?? [];

        return $this->isStarted;
    }

    public function set(string $key, $value): void
    {
        $this->session[$key] = $value;
    }

    public function get(string $key, $default = null)
    {
        return $this->session[$key] ?? $default;
    }

    public function unset(string $key): void
    {
        unset($this->session[$key]);
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->session);
    }

    public function clear(): void
    {
        $this->session = [];
    }

    public function destroy(): void
    {
        $this->session = [];
        $this->close();
        $this->id = null;
    }

    public function getId(): ?string
    {
        return $this->id;
    }

    public function regenerateId(): bool
    {
        $this->id = $this->generateId();
        $this->isRegenerated = true;

        return true;
    }

    private function generateId(): string
    {
        return bin2hex(random_bytes(16)); // OWASP recommendation
    }

    public function close(): bool
    {
        if ($this->isStarted === false) {
            return false;
        }

        // I think there were some issues with overwriting the $_SESSION variable directly
        $removed = array_diff(array_keys($_SESSION), array_keys($this->session));
        foreach ($this->session as $key => $value) {
            $_SESSION[$key] = $value;
        }

        foreach ($removed as  $key) {
            unset($_SESSION[$key]);
        }
        $closed = session_write_close();

        $this->isStarted = $closed === false;

        return $this->isRegenerated ? $this->regenerateSessionData() : $closed;
    }

    /**
     * Copy session data to new ID
     */
    private function regenerateSessionData(): bool
    {
        $this->isRegenerated = false;
        $session = $_SESSION; // data still seems to be here
        $this->start($this->id); // start session with new session ID
        $this->session = $session; // kansas city shuffle

        return $this->close(); // save
    }
}
```

## Resources

- https://paul-m-jones.com/post/2016/04/12/psr-7-and-session-cookies/
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- https://github.com/mezzio/mezzio-session
- https://github.com/yiisoft/session
