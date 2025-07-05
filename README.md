# SanjibJWT \ud83d\udd12

A secure, lightweight, and feature-rich JWT (JSON Web Token) implementation for PHP applications. Built with security and simplicity in mind, SanjibJWT provides everything you need to implement secure token-based authentication.

## Features

- Secure by Default (HMAC-SHA256, IP-based access, server map rotation)
- Zero dependencies, easy integration
- Custom header validation
- Configurable token expiration
- Stateless authentication

## Installation

### Composer (Recommended)
```bash
composer require sanjib/jwt
```

### Manual
1. Download `SanjibJWT.php`
2. Include it in your project:
   ```php
   require_once 'path/to/SanjibJWT.php';
   ```

## Quick Start

```php
use SanjibJWT\SanjibJWT;

$jwt = new SanjibJWT([
    'secret' => 'your-secure-secret-key',
    'access_token_expire' => 3600
]);

$token = $jwt->createToken([
    'user_id' => 123,
    'username' => 'sanjib'
]);

$payload = $jwt->validateToken($token['access_token']);

if ($payload) {
    echo "Welcome back, User #" . $payload['user_id'];
} else {
    echo "Invalid token: " . $jwt->getLastError();
}
```

## Configuration

| Option                | Type   | Default      | Description                              |
|-----------------------|--------|--------------|------------------------------------------|
| `secret`              | string | (required)   | Secret key for signing tokens            |
| `algorithm`           | string | 'HS256'      | Signing algorithm                        |
| `leeway`              | int    | 60           | Leeway in seconds for clock skew         |
| `access_token_expire` | int    | 3600         | Token expiration in seconds              |
| `allowed_ips`         | array  | []           | Restrict token usage to these IPs        |
| `require_https`       | bool   | true         | Require HTTPS for token validation       |

## Security Best Practices

- Always use HTTPS in production
- Rotate your secret key periodically
- Set appropriate token expiration times
- Validate all token claims in your application
- Use IP restrictions when possible
- Never expose your secret key in client-side code

## License

MIT License
