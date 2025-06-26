# Available Modules

Each module can be turned on simply by importing it and the side-effects take care of the rest.
Not all the capabilities of authboss are represented by a module, see [Use Cases](#use-cases)
to view the supported use cases as well as how to use them in your app.

**Note**: The two factor packages do not enable via side-effect import, see their documentation
for more information.

Name      | Import Path                               | Description
----------|-------------------------------------------|------------
Auth      | github.com/aarondl/authboss/v3/auth     | Database password authentication for users.
Confirm   | github.com/aarondl/authboss/v3/confirm  | Prevents login before e-mail verification.
Expire    | github.com/aarondl/authboss/v3/expire   | Expires a user's login
Lock      | github.com/aarondl/authboss/v3/lock     | Locks user accounts after authentication failures.
Logout    | github.com/aarondl/authboss/v3/logout   | Destroys user sessions for auth/oauth2.
OAuth1    | github.com/stephenafamo/authboss-oauth1      | Provides oauth1 authentication for users.
OAuth2    | github.com/aarondl/authboss/v3/oauth2   | Provides oauth2 authentication for users.
Recover   | github.com/aarondl/authboss/v3/recover  | Allows for password resets via e-mail.
Register  | github.com/aarondl/authboss/v3/register | User-initiated account creation.
Remember  | github.com/aarondl/authboss/v3/remember | Persisting login sessions past session cookie expiry.
OTP       | github.com/aarondl/authboss/v3/otp      | One time passwords for use instead of passwords.
Twofactor | github.com/aarondl/authboss/v3/otp/twofactor | Regenerate recovery codes for 2fa.
Totp2fa   | github.com/aarondl/authboss/v3/otp/twofactor/totp2fa | Use Google authenticator-like things for a second auth factor.
Sms2fa    | github.com/aarondl/authboss/v3/otp/twofactor/sms2fa | Use a phone for a second auth factor.
