<img src="http://i.imgur.com/fPIgqLg.jpg"/>

# Authboss

[![GoDoc](https://img.shields.io/badge/godoc-reference-5272B4)](https://pkg.go.dev/mod/github.com/aarondl/authboss/v3)
![ActionsCI](https://github.com/aarondl/authboss/workflows/test/badge.svg)
[![Mail](https://img.shields.io/badge/mail%20list-authboss-lightgrey.svg)](https://groups.google.com/a/volatile.tech/forum/#!forum/authboss)
![Go Coverage](https://img.shields.io/badge/coverage-84.9%25-brightgreen.svg?longCache=true&style=flat)
[![Go Report Card](https://goreportcard.com/badge/github.com/aarondl/authboss)](https://goreportcard.com/report/github.com/aarondl/authboss)

Authboss is a modular authentication system for the web.

It has several modules that represent authentication and authorization features that are common
to websites in general so that you can enable as many as you need, and leave the others out.
It makes it easy to plug in authentication to an application and get a lot of functionality
for (hopefully) a smaller amount of integration effort.

# New to v2?

v1 -> v2 was a very big change. If you're looking to upgrade there is a general guide in
[tov2.md](tov2.md) in this project.

# New to v3?

v2 -> v3 was not a big change, it simply changed the project to use Go modules.
Authboss no longer supports GOPATH as of version 3

# Why use Authboss?

Every time you'd like to start a new web project, you really want to get to the heart of what you're
trying to accomplish very quickly and it would be a sure bet to say one of the systems you're excited
about implementing and innovating on is not authentication. In fact it's very much the opposite: it's
one of those things that you have to do and one of those things you loathe to do. Authboss is supposed
to remove a lot of the tedium that comes with this, as well as a lot of the chances to make mistakes.
This allows you to care about what you're intending to do, rather than care about ancillary support
systems required to make what you're intending to do happen.

Here are a few bullet point reasons you might like to try it out:

* Saves you time (Authboss integration time should be less than re-implementation time)
* Saves you mistakes (at least using Authboss, people can bug fix as a collective and all benefit)
* Should integrate with or without any web framework

# [Click Here To Get Started](https://volatiletech.github.io/authboss/#/migration)

# Readme Table of Contents
<!-- TOC -->

- [Authboss](#authboss)
- [New to v2?](#new-to-v2)
- [New to v3?](#new-to-v3)
- [Why use Authboss?](#why-use-authboss)
- [Readme Table of Contents](#readme-table-of-contents)
- [Getting Started](#getting-started)
    - [App Requirements](#app-requirements)
        - [CSRF Protection](#csrf-protection)
        - [Request Throttling](#request-throttling)
    - [Integration Requirements](#integration-requirements)
        - [Middleware](#middleware)
        - [Configuration](#configuration)
        - [Storage and Core implementations](#storage-and-core-implementations)
        - [ServerStorer implementation](#serverstorer-implementation)
        - [User implementation](#user-implementation)
        - [Values implementation](#values-implementation)
    - [Config](#config)
        - [Paths](#paths)
        - [Modules](#modules)
        - [Mail](#mail)
        - [Storage](#storage)
        - [Core](#core)
- [Available Modules](#available-modules)
- [Middlewares](#middlewares)
- [Use Cases](#use-cases)
    - [Get Current User](#get-current-user)
    - [Reset Password](#reset-password)
    - [User Auth via Password](#user-auth-via-password)
    - [User Auth via OAuth1](#user-auth-via-oauth1)
    - [User Auth via OAuth2](#user-auth-via-oauth2)
    - [User Registration](#user-registration)
    - [Confirming Registrations](#confirming-registrations)
    - [Password Recovery](#password-recovery)
    - [Remember Me](#remember-me)
    - [Locking Users](#locking-users)
    - [Expiring User Sessions](#expiring-user-sessions)
    - [One Time Passwords](#one-time-passwords)
    - [Two Factor Authentication](#two-factor-authentication)
        - [Two-Factor Recovery](#two-factor-recovery)
        - [Two-Factor Setup E-mail Authorization](#two-factor-setup-e-mail-authorization)
        - [Time-Based One Time Passwords 2FA (totp)](#time-based-one-time-passwords-2fa-totp)
            - [Adding 2fa to a user](#adding-2fa-to-a-user)
            - [Removing 2fa from a user](#removing-2fa-from-a-user)
            - [Logging in with 2fa](#logging-in-with-2fa)
            - [Using Recovery Codes](#using-recovery-codes)
        - [Text Message 2FA (sms)](#text-message-2fa-sms)
            - [Adding 2fa to a user](#adding-2fa-to-a-user-1)
            - [Removing 2fa from a user](#removing-2fa-from-a-user-1)
            - [Logging in with 2fa](#logging-in-with-2fa-1)
            - [Using Recovery Codes](#using-recovery-codes-1)
    - [Rendering Views](#rendering-views)
        - [HTML Views](#html-views)
        - [JSON Views](#json-views)
        - [Data](#data)

<!-- /TOC -->

# Getting Started

To get started with Authboss in the simplest way, is to simply create a Config, populate it
with the things that are required, and start implementing [use cases](#use-cases). The use
cases describe what's required to be able to use a particular piece of functionality,
or the best practice when implementing a piece of functionality. Please note the
[app requirements](#app-requirements) for your application as well
[integration requirements](#integration-requirements) that follow.

Of course the standard practice of fetching the library is just the beginning:

```bash
# Get the latest, you must be using Go modules as of v3 of Authboss.
go get -u github.com/aarondl/authboss/v3
```

Here's a bit of starter code that was stolen from the sample.

```go
ab := authboss.New()

ab.Config.Storage.Server = myDatabaseImplementation
ab.Config.Storage.SessionState = mySessionImplementation
ab.Config.Storage.CookieState = myCookieImplementation

ab.Config.Paths.Mount = "/authboss"
ab.Config.Paths.RootURL = "https://www.example.com/"

// This is using the renderer from: github.com/aarondl/authboss
ab.Config.Core.ViewRenderer = abrenderer.NewHTML("/auth", "ab_views")
// Probably want a MailRenderer here too.


// This instantiates and uses every default implementation
// in the Config.Core area that exist in the defaults package.
// Just a convenient helper if you don't want to do anything fancy.
 defaults.SetCore(&ab.Config, false, false)

if err := ab.Init(); err != nil {
    panic(err)
}

// Mount the router to a path (this should be the same as the Mount path above)
// mux in this example is a chi router, but it could be anything that can route to
// the Core.Router.
mux.Mount("/authboss", http.StripPrefix("/authboss", ab.Config.Core.Router))
```

For a more in-depth look you **definitely should** look at the authboss sample to see what a full 
implementation looks like. This will probably help you more than any of this documentation.

[https://github.com/aarondl/authboss-sample](https://github.com/aarondl/authboss-sample)

## App Requirements

Authboss does a lot of things, but it doesn't do some of the important things that are required by
a typical authentication system, because it can't guarantee that you're doing many of those things
in a different way already, so it punts the responsibility.

### CSRF Protection

What this means is you should apply a middleware that can protect the application from csrf
attacks or you may be vulnerable. Authboss previously handled this but it took on a dependency
that was unnecessary and it complicated the code. Because Authboss does not render views nor
consumes data directly from the user, it no longer does this.

### Request Throttling

Currently Authboss is vulnerable to brute force attacks because there are no protections on
it's endpoints. This again is left up to the creator of the website to protect the whole website
at once (as well as Authboss) from these sorts of attacks.

## Integration Requirements

In terms of integrating Authboss into your app, the following things must be considered.

### Middleware

There are middlewares that are required to be installed in your middleware stack if it's
all to function properly, please see [Middlewares](#middlewares) for more information.

### Configuration

There are some required configuration variables that have no sane defaults and are particular
to your app:

* Config.Paths.Mount
* Config.Paths.RootURL

### Storage and Core implementations

Everything under Config.Storage and Config.Core are required and you must provide them,
however you can optionally use default implementations from the
[defaults package](https://github.com/aarondl/authboss/tree/master/defaults).
This also provides an easy way to share implementations of certain stack pieces (like HTML Form Parsing).
As you saw in the example above these can be easily initialized with the `SetCore` method in that
package.

The following is a list of storage interfaces, they must be provided by the implementer. Server is a
very involved implementation, please see the additional documentation below for more details.

* Config.Storage.Server
* Config.Storage.SessionState
* Config.Storage.CookieState (only for "remember me" functionality)

The following is a list of the core pieces, these typically are abstracting the HTTP stack.
Out of all of these you'll probably be mostly okay with the default implementations in the
defaults package but there are two big exceptions to this rule and that's the ViewRenderer
and the MailRenderer. For more information please see the use case [Rendering Views](#rendering-views)

* Config.Core.Router
* Config.Core.ErrorHandler
* Config.Core.Responder
* Config.Core.Redirector
* Config.Core.BodyReader
* Config.Core.ViewRenderer
* Config.Core.MailRenderer
* Config.Core.Mailer
* Config.Core.Logger

### ServerStorer implementation

The [ServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#ServerStorer) is
meant to be upgraded to add capabilities depending on what modules you'd like to use.
It starts out by only knowing how to save and load users, but the `remember` module as an example
needs to be able to find users by remember me tokens, so it upgrades to a
[RememberingServerStorer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#RememberingServerStorer)
which adds these abilities.

Your `ServerStorer` implementation does not need to implement all these additional interfaces
unless you're using a module that requires it. See the [Use Cases](#use-cases) documentation to know what the requirements are.

### User implementation

Users in Authboss are represented by the
[User interface](https://pkg.go.dev/github.com/aarondl/authboss/v3/#User). The user
interface is a flexible notion, because it can be upgraded to suit the needs of the various modules.

Initially the User must only be able to Get/Set a `PID` or primary identifier. This allows the authboss
modules to know how to refer to him in the database. The `ServerStorer` also makes use of this
to save/load users.

As mentioned, it can be upgraded, for example suppose now we want to use the `confirm` module,
in that case the e-mail address now becomes a requirement. So the `confirm` module will attempt
to upgrade the user (and panic if it fails) to a
[ConfirmableUser](https://pkg.go.dev/github.com/aarondl/authboss/v3/#ConfirmableUser)
which supports retrieving and setting of confirm tokens, e-mail addresses, and a confirmed state.

Your `User` implementation does not need to implement all these additional user interfaces unless you're
using a module that requires it. See the [Use Cases](#use-cases) documentation to know what the
requirements are.

### Values implementation

The [BodyReader](https://pkg.go.dev/github.com/aarondl/authboss/v3/#BodyReader)
interface in the Config returns
[Validator](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Validator) implementations
which can be validated. But much like the storer and user it can be upgraded to add different
capabilities.

A typical `BodyReader` (like the one in the defaults package) implementation checks the page being
requested and switches on that to parse the body in whatever way
(msgpack, json, url-encoded, doesn't matter), and produce a struct that has the ability to
`Validate()` it's data as well as functions to retrieve the data necessary for the particular
valuer required by the module.

An example of an upgraded `Valuer` is the
[UserValuer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#UserValuer)
which stores and validates the PID and Password that a user has provided for the modules to use.

Your body reader implementation does not need to implement all valuer types unless you're
using a module that requires it. See the [Use Cases](#use-cases) documentation to know what the
requirements are.

## Config

The config struct is an important part of Authboss. It's the key to making Authboss do what you
want with the implementations you want. Please look at it's code definition as you read the
documentation below, it will make much more sense.

[Config Struct Documentation](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Config)

### Paths

Paths are the paths that should be redirected to or used in whatever circumstance they describe.
Two special paths that are required are `Mount` and `RootURL` without which certain authboss
modules will not function correctly. Most paths get defaulted to `/` such as after login success
or when a user is locked out of their account.

### Modules

Modules are module specific configuration options. They mostly control the behavior of modules.
For example `RegisterPreserveFields` decides a whitelist of fields to allow back into the data
to be re-rendered so the user doesn't have to type them in again.

### Mail

Mail sending related options.

### Storage

These are the implementations of how storage on the server and the client are done in your
app. There are no default implementations for these at this time. See the [Godoc](https://pkg.go.dev/mod/github.com/aarondl/authboss/v3) for more information
about what these are.

### Core

These are the implementations of the HTTP stack for your app. How do responses render? How are
they redirected? How are errors handled?

For most of these there are default implementations from the
[defaults package](https://github.com/aarondl/authboss/tree/master/defaults) available, but not for all.
See the package documentation for more information about what's available.

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

# Middlewares

The only middleware that's truly required is the `LoadClientStateMiddleware`, and that's because it
enables session and cookie handling for Authboss. Without that, it's not a very useful piece of
software.

The remaining middlewares are either the implementation of an entire module (like expire),
or a key part of a module. For example you probably wouldn't want to use the lock module
without the middleware that would stop a locked user from using an authenticated resource,
because then locking wouldn't be useful unless of course you had your own way of dealing
with locking, which is why it's only recommended, and not required. Typically you will
use the middlewares if you use the module.

Name | Requirement | Description
---- | ----------- | -----------
[Middleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Middleware) | Recommended | Prevents unauthenticated users from accessing routes.
[LoadClientStateMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.LoadClientStateMiddleware) | **Required** | Enables cookie and session handling
[ModuleListMiddleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Authboss.ModuleListMiddleware) | Optional | Inserts a loaded module list into the view data
[confirm.Middleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/confirm/#Middleware) | Recommended with confirm | Ensures users are confirmed or rejects request
[expire.Middleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/expire/#Middleware) | **Required** with expire | Expires user sessions after an inactive period
[lock.Middleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/lock/#Middleware) | Recommended with lock | Rejects requests from locked users
[remember.Middleware](https://pkg.go.dev/github.com/aarondl/authboss/v3/remember/#Middleware) | Recommended with remember | Logs a user in from a remember cookie


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

## Rendering Views

The authboss rendering system is simple. It's defined by one interface: [Renderer](https://pkg.go.dev/github.com/aarondl/authboss/v3/#Renderer)

The renderer knows how to load templates, and how to render them with some data and that's it.
So let's examine the most common view types that you might want to use.

### HTML Views

When your app is a traditional web application and is generating it's HTML
serverside using templates this becomes a small wrapper on top of your rendering
setup. For example if you're using `html/template` then you could just use
`template.New()` inside the `Load()` method and store that somewhere and call
`template.Execute()` in the `Render()` method.

There is also a very basic renderer: [Authboss
Renderer](https://github.com/aarondl/authboss-renderer) which has some very
ugly built in views and the ability to override them with your own if you don't
want to integrate your own rendering system into that interface.

### JSON Views

If you're building an API that's mostly backed by a javascript front-end, then you'll probably
want to use a renderer that converts the data to JSON. There is a simple json renderer available in
the [defaults package](https://github.com/aarondl/authboss/tree/master/defaults) package if you wish to
use that.

### Data

The most important part about this interface is the data that you have to render.
There are several keys that are used throughout authboss that you'll want to render in your views.

They're in the file [html_data.go](https://github.com/aarondl/authboss/blob/master/html_data.go)
and are constants prefixed with `Data`. See the documentation in that file for more information on
which keys exist and what they contain.

The default [responder](https://pkg.go.dev/github.com/aarondl/authboss/v3/defaults/#Responder)
also happens to collect data from the Request context, and hence this is a great place to inject
data you'd like to render (for example data for your html layout, or csrf tokens).
