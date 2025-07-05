# 🔒 Security Best Practices for SanjibJWT

1. **Always use HTTPS in production**
   - Ensure all communication between clients and your server is encrypted.
   - Prevents token interception and man-in-the-middle attacks.

2. **Rotate your secret key periodically**
   - Change your JWT signing secret on a regular schedule.
   - Invalidate tokens signed with old secrets if possible.

3. **Set appropriate token expiration times**
   - Use short-lived tokens to minimize risk if a token is leaked.
   - Adjust `access_token_expire` in your configuration as needed.

4. **Validate all token claims in your application**
   - Always check `exp`, `iat`, `nbf`, and any custom claims.
   - Ensure tokens are only accepted if all claims are valid for your use case.

5. **Use IP restrictions when possible**
   - Limit token usage to known or trusted IP addresses.
   - Configure the `allowed_ips` option in SanjibJWT.

6. **Never expose your secret key in client-side code**
   - Keep your JWT secret server-side only.
   - Never embed secrets in JavaScript, HTML, or public repositories.

---

By following these best practices, you help ensure that your JWT-based authentication remains secure and robust. For more details, see the [README.md](./README.md) and [official JWT security guidelines](https://jwt.io/introduction/).
