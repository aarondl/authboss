# Use Cases

## Get Current User

CurrentUser can be retrieved by calling
[Authboss.CurrentUser](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.CurrentUser)
but a pre-requisite is that
[Authboss.LoadClientState](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientState)
has been called first to load the client state into the request context.
This is typically achieved by using the
[Authboss.LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware), but can
be done manually as well.

## Reset Password

Updating a user's password is non-trivial for several reasons:

1. The bcrypt algorithm must have the correct cost, and also be being used.
1. The user's remember me tokens should all be deleted so that previously authenticated sessions are invalid
1. Optionally the user should be logged out (**not taken care of by UpdatePassword**)

In order to do this, we can use the
[Authboss.UpdatePassword](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.UpdatePassword)
method. This ensures the above facets are taken care of which the exception of the logging out part.

If it's also desirable to have the user logged out, please use the following methods to erase
all known sessions and cookies from the user.

* [authboss.DelKnownSession](https://pkg.go.dev/github.com/aarondl/authboss/v3/#DelKnownSession)
* [authboss.DelKnownCookie](https://pkg.go.dev/github.com/aarondl/authboss/v3/#DelKnownCookie)

*Note: DelKnownSession has been deprecated for security reasons*

## User Auth via Password

| Info and Requirements |          |
| --------------------- | -------- |
Module        | auth
Pages         | login
Routes        | /login
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session and Cookie
ServerStorer  | [ServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#ServerStorer)
User          | [AuthableUser](https://pkg.go.dev/github.com/aarondl/authboss/v3/#AuthableUser)
Values        | [UserValuer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#UserValuer)
Mailer        | _None_

To enable this side-effect import the auth module, and ensure that the requirements above are met.
It's very likely that you'd also want to enable the logout module in addition to this.

Direct a user to `GET /login` to have them enter their credentials and log in.

## User Auth via OAuth1

| Info and Requirements |          |
| --------------------- | -------- |
Module        | oauth1
Pages         | _None_
Routes        | /oauth1/{provider}, /oauth1/callback/{provider}
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session
ServerStorer  | [OAuth1ServerStorer](https://pkg.go.dev/github.com/stephenafamo/authboss-oauth1?tab=doc#ServerStorer)
User          | [OAuth1User](https://pkg.go.dev/github.com/stephenafamo/authboss-oauth1?tab=doc#User)
Values        | _None_
Mailer        | _None_

This is a tougher implementation than most modules because there's a lot going on. In addition to the
requirements stated above, you must also configure the `oauth1.Providers`. It's a public variable in the module.

```go
import oauth1 "github.com/stephenafamo/authboss-oauth1"

oauth1.Providers = map[string]oauth1.Provider{}
```

The providers require an oauth1 configuration that's typical for the Go oauth1 package, but in addition
to that they need a `FindUserDetails` method which has to take the token that's retrieved from the oauth1
provider, and call an endpoint that retrieves details about the user (at LEAST user's uid).
These parameters are returned in `map[string]string` form and passed into the `oauth1.ServerStorer`.

Please see the following documentation for more details:

* [Package docs for oauth1](https://pkg.go.dev/github.com/stephenafamo/authboss-oauth1)
* [oauth1.Provider](https://pkg.go.dev/github.com/stephenafamo/authboss-oauth1?tab=doc#Provider)
* [oauth1.ServerStorer](https://pkg.go.dev/github.com/stephenafamo/authboss-oauth1/#OAuth1ServerStorer)

## User Auth via OAuth2

| Info and Requirements |          |
| --------------------- | -------- |
Module        | oauth2
Pages         | _None_
Routes        | /oauth2/{provider}, /oauth2/callback/{provider}
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session
ServerStorer  | [OAuth2ServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#OAuth2ServerStorer)
User          | [OAuth2User](https://pkg.go.dev/github.com/aarondl/authboss/v3/#OAuth2User)
Values        | _None_
Mailer        | _None_

This is a tougher implementation than most modules because there's a lot going on. In addition to the
requirements stated above, you must also configure the `OAuth2Providers` in the config struct.

The providers require an oauth2 configuration that's typical for the Go oauth2 package, but in addition
to that they need a `FindUserDetails` method which has to take the token that's retrieved from the oauth2
provider, and call an endpoint that retrieves details about the user (at LEAST user's uid).
These parameters are returned in `map[string]string` form and passed into the `OAuth2ServerStorer`.

Please see the following documentation for more details:

* [Package docs for oauth2](https://pkg.go.dev/github.com/aarondl/authboss/v3/oauth2/)
* [authboss.OAuth2Provider](https://pkg.go.dev/github.com/aarondl/authboss/v3/#OAuth2Provider)
* [authboss.OAuth2ServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#OAuth2ServerStorer)

## User Registration

| Info and Requirements |          |
| --------------------- | -------- |
Module        | register
Pages         | register
Routes        | /register
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session
ServerStorer  | [CreatingServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#CreatingServerStorer)
User          | [AuthableUser](https://pkg.go.dev/github.com/aarondl/authboss/v3/#AuthableUser), optionally [ArbitraryUser](https://pkg.go.dev/github.com/aarondl/authboss/v3/#ArbitraryUser)
Values        | [UserValuer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#UserValuer), optionally also [ArbitraryValuer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#ArbitraryValuer)
Mailer        | _None_

Users can self-register for a service using this module. You may optionally want them to confirm
themselves, which can be done using the confirm module.

The complicated part in implementing registrations are around the `RegisterPreserveFields`. This is to
help in the case where a user fills out many fields, and then say enters a password
which doesn't meet minimum requirements and it fails during validation. These preserve fields should
stop the user from having to type in all that data again (it's a whitelist). This **must** be used
in conjuction with `ArbitraryValuer` and although it's not a hard requirement `ArbitraryUser`
should be used otherwise the arbitrary values cannot be stored in the database.

When the register module sees arbitrary data from an `ArbitraryValuer`, it sets the data key
`authboss.DataPreserve` with a `map[string]string` in the data for when registration fails.
This means the (whitelisted) values entered by the user previously will be accessible in the
templates by using `.preserve.field_name`. Preserve may be empty or nil so use
`{{with ...}}` to make sure you don't have template errors.

There is additional [Godoc documentation](https://pkg.go.dev/mod/github.com/aarondl/authboss/v3#Config) on the `RegisterPreserveFields` config option as well as
the `ArbitraryUser` and `ArbitraryValuer` interfaces themselves.

## Confirming Registrations

| Info and Requirements |          |
| --------------------- | -------- |
Module        | confirm
Pages         | confirm
Routes        | /confirm
Emails        | confirm_html, confirm_txt
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware), [confirm.Middleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/confirm/#Middleware)
ClientStorage | Session
ServerStorer  | [ConfirmingServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#ConfirmingServerStorer)
User          | [ConfirmableUser](https://pkg.go.dev/github.com/aarondl/authboss/v3/#ConfirmableUser)
Values        | [ConfirmValuer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#ConfirmValuer)
Mailer        | Required

Confirming registrations via e-mail can be done with this module (whether or not done via the register
module).

A hook on register kicks off the start of a confirmation which sends an e-mail with a token for the user.
When the user re-visits the page, the `BodyReader` must read the token and return a type that returns
the token.

Confirmations carry two values in the database to prevent a timing attack. The selector and the
verifier, always make sure in the ConfirmingServerStorer you're searching by the selector and
not the verifier.

## Password Recovery

| Info and Requirements |          |
| --------------------- | -------- |
Module        | recover
Pages         | recover_start, recover_middle (not used for renders, only values), recover_end
Routes        | /recover, /recover/end
Emails        | recover_html, recover_txt
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session
ServerStorer  | [RecoveringServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#RecoveringServerStorer)
User          | [RecoverableUser](https://pkg.go.dev/github.com/aarondl/authboss/v3/#RecoverableUser)
Values        | [RecoverStartValuer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#RecoverStartValuer), [RecoverMiddleValuer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#RecoverMiddleValuer), [RecoverEndValuer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#RecoverEndValuer)
Mailer        | Required

The flow for password recovery is that the user is initially shown a page that wants their `PID` to
be entered. The `RecoverStartValuer` retrieves that on `POST` to `/recover`.

An e-mail is sent out, and the user clicks the link inside it and is taken back to `/recover/end`
as a `GET`, at this point the `RecoverMiddleValuer` grabs the token and will insert it into the data
to be rendered.

They enter their password into the form, and `POST` to `/recover/end` which sends the token and
the new password which is retrieved by `RecoverEndValuer` which sets their password and saves them.

Password recovery has two values in the database to prevent a timing attack. The selector and the
verifier, always make sure in the RecoveringServerStorer you're searching by the selector and
not the verifier.

## Remember Me

| Info and Requirements |          |
| --------------------- | -------- |
Module        | remember
Pages         | _None_
Routes        | _None_
Emails        | _None_
Middlewares   | LoadClientStateMiddleware,
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware), [remember.Middleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/remember/#Middleware)
ClientStorage | Session, Cookies
ServerStorer  | [RememberingServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#RememberingServerStorer)
User          | User
Values        | [RememberValuer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#RememberValuer) (not a Validator)
Mailer        | _None_

Remember uses cookie storage to log in users without a session via the `remember.Middleware`.
Because of this this middleware should be used high up in the stack, but it also needs to be after
the `LoadClientStateMiddleware` so that client state is available via the authboss mechanisms.

There is an intricacy to the `RememberingServerStorer`, it doesn't use the `User` struct at all,
instead it simply instructs the storer to save tokens to a pid and recall them just the same. Typically
in most databases this will require a separate table, though you could implement using pg arrays
or something as well.

A user who is logged in via Remember tokens is also considered "half-authed" which is a session
key (`authboss.SessionHalfAuthKey`) that you can query to check to see if a user should have
full rights to more sensitive data, if they are half-authed and they want to change their user
details for example you may want to force them to go to the login screen and put in their
password to get a full auth first. The `authboss.Middleware` has a boolean flag to `forceFullAuth`
which prevents half-authed users from using that route.

## Locking Users

| Info and Requirements |          |
| --------------------- | -------- |
Module        | lock
Pages         | _None_
Routes        | _None_
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware), [lock.Middleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/lock/#Middleware)
ClientStorage | Session
ServerStorer  | [ServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#ServerStorer)
User          | [LockableUser](https://pkg.go.dev/github.com/aarondl/authboss/v3/#LockableUser)
Values        | _None_
Mailer        | _None_

Lock ensures that a user's account becomes locked if authentication (both auth, oauth2, otp) are
failed enough times.

The middleware protects resources from locked users, without it, there is no point to this module.
You should put in front of any resource that requires a login to function.

## Expiring User Sessions

| Info and Requirements |          |
| --------------------- | -------- |
Module        | expire
Pages         | _None_
Routes        | _None_
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware), [expire.Middleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/expire/#Middleware)
ClientStorage | Session
ServerStorer  | _None_
User          | [User](https://pkg.go.dev/github.com/aarondl/authboss/v3/#User)
Values        | _None_
Mailer        | _None_

**Note:** Unlike most modules in Authboss you must call `expire.Setup()`
to enable this module. See the sample to see how to do this. This may be changed in the future.

Expire simply uses sessions to track when the last action of a user is, if that action is longer
than configured then the session is deleted and the user removed from the request context.

This middleware should be inserted at a high level (closer to the request) in the middleware chain
to ensure that "activity" is logged properly, as well as any middlewares down the chain do not
attempt to do anything with the user before it's removed from the request context.

## One Time Passwords

| Info and Requirements |          |
| --------------------- | -------- |
Module        | otp
Pages         | otp, otpadd, otpclear
Routes        | /otp/login, /otp/add, /otp/clear
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session and Cookie
ServerStorer  | [ServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#ServerStorer)
User          | [otp.User](https://pkg.go.dev/github.com/aarondl/authboss/v3/otp/#User)
Values        | [UserValuer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#UserValuer)
Mailer        | _None_

One time passwords can be useful if users require a backup password in case they lose theirs,
or they're logging in on an untrusted computer. This module allows users to add one time passwords,
clear them, or log in with them.

Logging in with a one time password instead of a password is identical to having logged in normally
with their typical password with the exception that the one time passwords are consumed immediately
upon use and cannot be used again.

`otp` should not be confused with two factor authentication. Although 2fa also uses one-time passwords
the `otp` module has nothing to do with it and is strictly a mechanism for logging in with an alternative
to a user's regular password.

## Two Factor Authentication

2FA in Authboss is implemented in a few separate modules: twofactor, totp2fa and sms2fa.

You should use two factor authentication in your application if you want additional security beyond
that of just simple passwords. Each 2fa module supports a different mechanism for verifying a second
factor of authentication from a user.

### Two-Factor Recovery

| Info and Requirements |          |
| --------------------- | -------- |
Module        | twofactor
Pages         | recovery2fa
Routes        | /2fa/recovery/regen
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session
ServerStorer  | [ServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#ServerStorer)
User          | [twofactor.User](https://pkg.go.dev/github.com/aarondl/authboss/v3/otp/twofactor/#User)
Values        | _None_
Mailer        | _None_

**Note:** Unlike most modules in Authboss you must construct a `twofactor.Recovery` and call `.Setup()`
on it to enable this module. See the sample to see how to do this. This may be changed in the future.

Package twofactor is all about the common functionality of providing backup codes for two factor
mechanisms. Instead of each module implementing backup codes on it's own, common functionality has
been put here including a route to regenerate backup codes.

Backup codes are useful in case people lose access to their second factor for authentication. This happens
when users lose their phones for example. When this occurs, they can use one of their backup-codes.

Backup codes are one-time use, they are bcrypted for security, and they only allow bypassing the 2fa
authentication part, they cannot be used in lieu of a user's password, for that sort of recovery see
the `otp` module.

### Two-Factor Setup E-mail Authorization

| Info and Requirements |          |
| --------------------- | -------- |
Module        | twofactor
Pages         | twofactor_verify
Routes        | /2fa/recovery/regen
Emails        | twofactor_verify_email_html, twofactor_verify_email_txt
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session
ServerStorer  | [ServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#ServerStorer)
User          | [twofactor.User](https://pkg.go.dev/github.com/aarondl/authboss/v3/otp/twofactor/#User)
Values        | [twofactor.EmailVerifyTokenValuer](https://pkg.go.dev/github.com/aarondl/authboss/v3/otp/twofactor/#EmailVerifyTokenValuer)
Mailer        | Required

To enable this feature simply turn on
`authboss.Config.Modules.TwoFactorEmailAuthRequired` and new routes and
middlewares will be installed when you set up one of the 2fa modules.

When enabled, the routes for setting up 2fa on an account are protected by a
middleware that will redirect to `/2fa/{totp,sms}/email/verify` where
Page `twofactor_verify` is displayed. The user is prompted to authorize the
addition of 2fa to their account. The data for this page contains `email` and
a `url` for the POST. The url is required because this page is shared between
all 2fa types.

Once they POST to the url, a token is stored in their session and an e-mail is
sent with that token. When they click the link that goes to
`/2fa/{totp,sms}/email/verify/end` with a token in the query string the session
token is verified and exchanged for a value that says they're verified and
lastly it redirects them to the setup URL for the type of 2fa they were
attempting to setup.

### Time-Based One Time Passwords 2FA (totp)

| Info and Requirements |          |
| --------------------- | -------- |
Module        | totp2fa
Pages         | totp2fa_{setup,confirm,remove,validate}, totp2fa_{confirm,remove}_success
Routes        | /2fa/totp/{setup,confirm,qr,remove,validate}
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session **(SECURE!)**
ServerStorer  | [ServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#ServerStorer)
User          | [totp2fa.User](https://pkg.go.dev/github.com/aarondl/authboss/v3/otp/twofactor/totp2fa/#User)
Values        | [TOTPCodeValuer](https://pkg.go.dev/github.com/aarondl/authboss/v3/otp/twofactor/totp2fa/#TOTPCodeValuer)
Mailer        | _None_

**Note:** Unlike most modules in Authboss you must construct a `totp2fa.TOTP` and call `.Setup()`
on it to enable this module. See the sample to see how to do this This may be changed in the future.

**Note:** To allow users to regenerate their backup codes, you must also use the `twofactor` module.

**Note:** Routes are protected by `authboss.Middleware` so only logged in users can access them.
You can configure whether unauthenticated users should be redirected to log in or are 404'd using
the `authboss.Config.Modules.RoutesRedirectOnUnathed` configuration flag.

#### Adding 2fa to a user

When a logged in user would like to add 2fa to their account direct them `GET /2fa/totp/setup`, the `GET`
on this page does virtually nothing so you don't have to use it, just `POST` immediately to have
a smoother flow for the user. **This puts the 2fa secret in their session temporarily meaning you must
have proper secure sessions for this to be secure.**

They will be redirected to `GET /2fa/totp/confirm` where the data will show `totp2fa.DataTOTPSecret`,
this is the key that user's should enter into their Google Authenticator or similar app. Once they've
added it they need to send a `POST /2fa/totp/confirm` with a correct code which removes the 2fa secret
from their session and permanently adds it to their `totp2fa.User` and 2fa is now enabled for them.
The data from the `POST` will contain a key `twofactor.DataRecoveryCodes` that contains an array
of recovery codes for the user.

If you wish to show the user a QR code, `GET /2fa/totp/qr` at any time during or after totp2fa setup
will return a 200x200 png QR code that they can scan.

#### Removing 2fa from a user

A user begins by going to `GET /2fa/totp/remove` and enters a code which posts to `POST /2fa/totp/remove`
and if it's correct they're shown a success page and 2fa is removed from them, if not they get
validation errors.

#### Logging in with 2fa

When a user goes to log in, the `totp` module checks the user after they log in for the presence of
a totp2fa secret, if there is one it does not give them a logged in session value immediately and
redirects them to `GET /2fa/totp/validate` where they must enter a correct code to `POST /2fa/totp/validate`
if the code is correct they're logged in normally as well as they get the session value
`authboss.Session2FA` set to `"totp"` to prove that they've authenticated with two factors.

#### Using Recovery Codes

Both when logging in and removing totp2fa from an account, a recovery code may be used instead. They can
`POST` to the same url, they simply send a different form field. The recovery code is consumed on use
and may not be used again.

### Text Message 2FA (sms)

Package sms2fa uses sms shared secrets as a means to authenticate a user with a second factor:
their phone number.

| Info and Requirements |          |
| --------------------- | -------- |
Module        | sms2fa
Pages         | sms2fa_{setup,confirm,remove,validate}, sms2fa_{confirm,remove}_success
Routes        | /2fa/{setup,confirm,remove,validate}
Emails        | _None_
Middlewares   | [LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware)
ClientStorage | Session (**SECURE!**)
ServerStorer  | [ServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#ServerStorer)
User          | [sms2fa.User](https://pkg.go.dev/github.com/aarondl/authboss/v3/otp/twofactor/sms2fa/#User), [sms2fa.SMSNumberProvider](https://pkg.go.dev/github.com/aarondl/authboss/v3/otp/twofactor/sms2fa/#SMSNumberProvider)
Values        | [SMSValuer](https://pkg.go.dev/github.com/aarondl/authboss/v3/otp/twofactor/sms2fa/#SMSValuer), [SMSPhoneNumberValuer](https://pkg.go.dev/github.com/aarondl/authboss/v3/otp/twofactor/sms2fa/#SMSPhoneNumberValuer)
Mailer        | _None_

**Note:** Unlike most modules in Authboss you must construct a `sms2fa.SMS` and call `.Setup()`
on it to enable this module. See the sample to see how to do this. This may be changed in the future.

**Note:** To allow users to regenerate their backup codes, you must also use the `twofactor` module.

**Note:** Routes are protected by `authboss.Middleware` so only logged in users can access them.
You can configure whether unauthenticated users should be redirected to log in or are 404'd using
the `authboss.Config.Modules.RoutesRedirectOnUnathed` configuration flag.

**Note:** sms2fa always stores the code it's expecting in the user's session therefore **you must
have secure sessions or the code itself is not secure!**

**Note:** sms2fa pages all send codes via sms on `POST` when no data code is given. This is also how
users can resend the code in case they did not get it (for example a second
`POST /2fa/sms/{confirm,remove}` with no form-fields filled in will end up resending the code).

**Note:** Sending sms codes is rate-limited to 1 sms/10 sec for that user, this is controlled by placing
a timestamp in their session to prevent abuse.

#### Adding 2fa to a user

When a logged in user would like to add 2fa to their account direct them `GET /2fa/sms/setup` where
they must enter a phone number. If the logged in user also implements `sms2fa.SMSNumberProvider` then
this interface will be used to retrieve a phone number (if it exists) from the user and put it in
`sms2fa.DataSMSPhoneNumber` so that the user interface can populate it for the user, making it convenient
to re-use an already saved phone number inside the user.

Once they `POST /2fa/sms/setup` with a phone number, the `sms2fa.Sender` interface will be
invoked to send the SMS code to the user and they will be redirected to `GET /2fa/sms/confirm` where
they enter the code they received which does a `POST /2fa/sms/confirm` to store the phone number
they were confirming permanently on their user using `sms2fa.User` which enables sms2fa for them.
The data from the `POST` will contain a key `twofactor.DataRecoveryCodes` that contains an array
of recovery codes for the user.

#### Removing 2fa from a user

A user begins by going to `GET /2fa/sms/remove`. This page does nothing on it's own. In order to
begin the process `POST /2fa/sms/remove` with no data (or a recovery code to skip needing the sms code)
to send the sms code to the user. Then they can `POST /2fa/sms/remove` again with the correct code
to have it permanently removed.

#### Logging in with 2fa

When a user goes to log in, the `sms` module checks the user after they log in for the presence of
a sms2fa phone number, if there is one it does not give them a logged in session value but instead
sends an SMS code to their configured number and and redirects them to `GET /2fa/sms/validate`
where they must enter a correct code to `POST /2fa/totp/validate`. If the code is correct they're
logged in normally as well as they get the session value `authboss.Session2FA` set to `"sms"` to prove
that they've authenticated with two factors.

#### Using Recovery Codes

Same as totp2fa above.