# Changelog

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [3.5.0] - 2023-12-30

### Added

- Localization interface (thanks @stepehenafamo)

- ### Security

- Bump crypto dependency

## [3.4.0] - 2023-11-19

### Added

- Configurable hashing (thanks @larrycinnabar, @stephenafamo)
- Compatability with http.ResponseController.Unwrap interface (thanks @stephenafamo)

### Security

- Bump dependencies, change min Go version to 1.20

## [3.3.0] - 2023-09-28

### Added

- Added a way for storers to present secondary emails for recovery.

### Security

- Fix a critical issue in totp backup code rejection

## [3.2.2] - 2023-03-12

### Security

- Upgrade dependencies

## [3.2.1] - 2022-10-10

### Security

- Change it such that events are fired around recovery. Some important events
  were not occurring despite being logged in that would manage state like
  remember cookies, locking state, etc.

  A significant side effect of this is that when 2fa is currently turned on on
  an account, it could be bypassed by using the Recover functionality with the
  `RecoverLoginAfterRecovery` feature which was not otherwise flagged as a
  dangerous option.

  While it is true that recover uses an email to invoke the flow and therefore
  some second factor has been utilizied, it should be considered insecure to
  bypass an authenticator or sms verification for any login and therefore
  this large change in behavior is being shipped as a security fix (meaning it
  becomes a minor change).

## [3.2.0] - 2021-08-11

### Added

- Add additional events so users can take domain-specific actions when a user
  adds or removes 2fa.

## [3.1.1] - 2021-07-01

### Fixed

- Fix a test that had gone red

## [3.1.0] - 2021-07-01

### Added

- Add an optional interface in totp2fa that when implemented on the authboss
  User struct can prevent re-use of totp 2fa codes. This normally should have
  been a requirement for this module's usage but due to backward compatibility
  it's being added as optional and will become mandatory in the next major
  version.

### Changed

- Change totp/sms email validation to delete the "email validation" session
  key after successfully adding 2fa to an account. This requires a second
  email verification in the same session if a user deletes and re-adds
  2fa. This change is a behavior change but is not worthy of a larger version
  bump and should slightly increase security.
- Change "Successfully Authenticated" flash message when logging in with
  totp/sms 2fa methods. This was a difference between logging in with the
  auth module. It now has no flash message.

## [3.0.5] - 2021-05-18

- Fix an open redirect security issue. This is technically a breaking change
  if you are redirecting to some other site or front-end that's not on your
  server.

## [3.0.4] - 2021-04-27

### Changed

- Change qrcode endpoint for totp to try to prevent caching

## [3.0.3] - 2021-02-14

### Fixed

- Fix that EventRecoverStart/EventRecoverEnd were not being called.

### Changed

- Change Remember module to listen to `After(EventRecoverEnd)` in order to
  invoke its handler to delete the remember cookie & tokens. This previously
  was not being called so it could be viewed as new behavior though this only
  applies if you are using both `remember` and `recover` modules.

### Deprecate

- EventPasswordReset is used nowhere and is no longer intended to be used.

## [3.0.2] - 2020-09-17

### Fixed

- Fix an open redirect security issue. This is technically a breaking change
  if you are redirecting to some other site or front-end that's not on your
  server.

## [3.0.1] - 2020-08-25

### Added

- Add the ability to carry query string parameters in the redirection to and
  away from the login page.

## [3.0.0] - 2020-07-03

### Added

- Move to Go modules

## [2.4.1] - 2020-05-18

### Fixed

Fix a security issue where a user could brute-force a password based on
differing responses that are returned from the site when the incorrect password
is entered versus the correct password.

This comes with a slight change in behavior to minimize differences between the
code paths of a correct vs incorrect password: The "attempt" time is always
bumped in the DB no matter if it was the right or wrong password when being
rejected for locking.

## [2.4.0] - 2020-02-07

### Added

- Add config option MailNoGoroutine which prevents the modules from using a
  goroutine to launch the mailer. This is important because the context
  that it passes from the http request will be cancelled in a race condition
  and will affect mailer implementations that honor context cancellation.

## [2.3.2] - 2020-01-30

### Fixed

- Fix many "lint" type errors (thanks @frederikhors)

## [2.3.1] - 2020-01-28

### Added

- Logout events (Before & After) for deletion of a users session
  (thanks @abelkuruvilla)

### Changed

- Calls to Email() will now merge ctx data from the passed in ctx so it's
  available in the template, just like calls to Render() (thanks @Gys)

### Fixed

- Fix one of the mocks that were no longer in sync with an interface

## [2.3.0] - 2019-03-30

### Added

- Add VerifyPassword method to hide the bcrypt implementation details when
  authboss consumer code wants to verify the password out of band.
- ClientStateResponseWriter now supports the http.Hijacker interface if the
  underlying ResponseWriter does (thanks @tobias-kuendig)
- DelAllSession is a new method called both by Expire and Logout (in addition
  to still calling DelKnownSession etc. as they do now) to ensure that
  conforming implementations of ClientStateReadWriter's delete all keys
  in the session.
- Config.Storage.SessionWhitelistKeys has been added in order to allow users
  to persist session variables past logout/expire.

### Fixed

- Fix bug where user's expiration time did not start until their first
  request after login.
- Fix bug where expired users could perform one request past their expiration
- Fix bug with missing imports (thanks @frederikhors)
- Fix bug with inverted remember me checkbox logic
- Fix validation not happening when user commences recovery

### Deprecated

- Deprecated DelKnownSession for DelAllSession. DelAllSession should be
  implemented by existing ClientStateReadWriters in order to prevent session
  values from leaking to a different user post-logout/expire.

## [2.2.0] - 2018-12-16

### Added

- Add e-mail confirmation before 2fa setup feature
- Add config value TwoFactorEmailAuthRequired
- Add a more flexible way of adding behaviors and requirements to
  authboss.Middleware. This API is at authboss.Middleware2 temporarily
  until we can make a breaking change.

### Fixed

- Fix a bug where GET /login would panic when no FormValueRedirect is
  provided. (thanks @rarguelloF)
- Fix a bug where lowercase password requirements in the default rules
  implementation were not being checked correctly (thanks @rarguelloF)
- Fix a bug in remember where a user would get half-authed even though they
  were logged in depending on middleware ordering.
- Fix a bug where if you were using lock/remember modules with 2fa they
  would fail since the events didn't contain the current user in the context
  as the auth module delivers them.
- Fix a bug with 2fa where a locked account could get a double response

### Deprecated

- Deprecate the config field ConfirmMethod in favor of MailRouteMethod. See
  documentation for these config fields to understand how to use them now.
- Deprecate Middleware/MountedMiddleware for Middleware2 and MountedMiddleware2
  as these new APIs are more flexible. When v3 hits (Mounted)Middleware2 will
  become just (Mounted)Middleware.
- Deprecate RoutesRedirectOnUnauthed in favor of ResponseOnUnauthed

## [2.1.1] - 2018-12-10

### Security

- Fix a bug with the 2fa code where a client that failed to log in to a user
  account got SessionTOTPPendingPID set to that user's pid. That user's pid
  was used as lookup for verify() method in totp/sms methods before current
  user was looked at meaning the logged in user could remove 2fa from the
  other user's account because of the lookup order.

## [2.1.0] - 2018-10-28

### Added

- Add Config option to defaults.HTTPRedirector to allow it to coerce redirect
  response codes to http.StatusOK to help make more regular APIs.
- Add Config option for MailRoot. This is a URL that overrides the typical
  URL building using Root/MountPath that recover and confirm do to enable
  creating mail links to a different location than where the API is hosted.
- Add a configuration option that allows confirm to change the method type
  it expects since in an API setting a GET is strange as there is body details.

### Changed

- defaults.HTTPRedirector now always responds with a "status": "success"
  when responding to an API unless there's a failure.
- defaults.JSONRenderer now renders a "status": "success" or "status": "failure"
  based on the presence of known failure keys (configurable, defaults to
  standard Authboss HTMLData errors).

### Fixed

- Fix a bug where content-types like 'application/json;charset=utf-8' would
  not trigger api responses in the default responder.
- Fix LoadCurrentUser error handling, it was swallowing errors when users were
  not logged in, changed to be consistent, now returns ErrUserNotFound just like
  CurrentUser.
- Fix a bug where EventAuth and EventAuthFailure were not being fired in the
  2fa modules which would stop users from becoming locked on 2fa failures
  or logging in without being confirmed.

## [2.0.0] - 2018-09-03

### Added

- Add sms2fa and totp2fa packages so users can use two factor authentication
- Add twofactor package to enable 2fa recovery codes for sms2fa and totp2fa
- Add OTP module so users can create one time passwords and use them to log in.
- Add more documentation about how RegisterPreserveFields works so people
  don't have to chase the godocs to figure out how to implement it.

### Changed

- authboss.Middleware now has boolean flags to provide more control over
  how unathenticated users are dealt with. It can now redirect users to
  the login screen with a redirect to the page they were attempting to reach
  and it can also protect against half-authed users and users who have
  not authenticated with two factor auth.

### Fixed

- Ensure all uses of crypto/rand.Read are replaced by io.ReadFull(rand.Reader)
  to ensure that we never get a read that's full of zeroes. This was a bug
  present in a uuid library, we don't want to make the same mistake.

## [2.0.0-rc6] - 2018-08-16

- LoadClientStateMiddleware no longer panics when LoadClientState fails.
  Instead it logs error messages and gives a 500 server error to users instead
  of returning no response from the server at all due to panic.

### Fixed

- Fix a bug where LoadClientState could return a nil request if the state
  returned nil instead of falling through.
- Fix Middlewares link in README
- Fix error message when forgetting authboss.LoadClientStateMiddleware to
  be a bit more indicative of what the problem might be.

## [2.0.0-rc5] - 2018-07-04

### Changed

- The upstream golang.org/x/oauth2 library has changed it's API, this fixes
  the breakage.

## [2.0.0-rc4] - 2018-06-27

### Changed

- RememberingServerStorer now has context on its methods

## [2.0.0-rc3] - 2018-05-25

### Changed

- Recover and Confirm now use split tokens

    The reason for this change is that there's a timing attack possible
    because of the use of memcmp() by databases to check if the token exists.
    By using a separate piece of the token as a selector, we use memcmp() in
    one place, but a crypto constant time compare in the other to check the
    other value, and this value cannot be leaked by timing, and since you need
    both to recover/confirm as the user, this attack should now be mitigated.

    This requires users to implement additional fields on the user and rename
    the Storer methods.

## [2.0.0-rc2] - 2018-05-14

Mostly rewrote Authboss by changing many of the core interfaces. This release
is instrumental in providing better support for integrating with many web frameworks
and setups.

### Added

- v2 Upgrade guide (tov2.md)

- API/JSON Support

    Because of the new abstractions it's possible to implement body readers,
    responders, redirectors and renderers that all speak JSON (or anything else for that
    matter). There are a number of these that exist already in the defaults package.

### Changed

- The core functionality of authboss is now delivered over a set of interfaces

    This change was fairly massive. We've abstracted the HTTP stack completely
    so that authboss isn't really doing things like issuing template renderings,
    it's just asking a small interface to do it instead. The reason for doing this
    was because the previous design was too inflexible and wouldn't integrate nicely
    with various frameworks etc. The defaults package helps fill in the gaps for typical
    use cases.

- Storage is now done by many small interfaces

    It became apparent than the old reflect-based mapping was a horrible solution
    to passing data back and forth between these structs. So instead we've created a
    much more verbose (but type safe) set of interfaces to govern which fields we need.

    Now we can check that our structs have the correct methods using variable declarations
    and there's no more confusion about how various types map back and forth inside the
    mystical `Bind` and `Unbind` methods.

    The downside to this of course is it's incredibly verbose to create a fully featured
    model, but I think that the benefits outweigh the downsides (see bugs in the past about
    different types being broken/not supported/not working correctly).

- Support for context.Context is now much better

    We had a few pull requests that kind of shoved context.Context support in the sides
    so that authboss would work in Google App Engine. With this release context is
    almost everywhere that an external system would be interacted with.

- Client State management rewritten

    The old method of client state management performed writes too frequently. By using a
    collection of state change events that are later applied in a single write operation at
    the end, we make it so we don't get duplicate cookies etc. The bad thing about this is
    that we have to wrap the ResponseWriter. But there's an UnderlyingResponseWriter
    interface to deal with this problem.

- Validation has been broken into smaller and hopefully nicer interfaces

    Validation needs to be handled by the BodyReader's set of returned structs. This punts
    validation outside of the realm of Authboss for the most part, but there's still
    helpful tools in the defaults package to help with validation if you're against writing
    rolling your own.

- Logout has been broken out into it's own module to avoid duplication inside login/oauth2
  since they perform the same function.

- Config is now a nested struct, this helps organize the properties a little better (but
  I hope you never mouse over the type definition in a code editor).

### Removed

- Notable removal of AllowInsecureLoginAfterConfirm

### Fixed

- Fix bug where e-mail with only a textbody would send blank e-mails

### Deprecated

- Use of gopkg.in, it's no longer a supported method of consuming authboss. Use
  manual vendoring, dep or vgo.

## [1.0.0] - 2015-08-02
### Changed
This change is potentially breaking, it did break the sample since the supporting struct was wrong for the data we were using.

**Lock:** The documentation was updated to reflect that the struct value for AttemptNumber is indeed an int64.
**Unbind:** Previously it would scrape the struct for the supported types (string, int, bool, time.Time, sql.Scanner/driver.Valuer)
and make them into a map. Now the field list will contain all types found in the struct.
**Bind:** Before this would only set the supported types (described above), now it attempts to set all values. It does check to ensure
the type in the attribute map matches what's in the struct before assignment.

## 2015-04-01 Refactor for Multi-tenancy
### Changed
This breaking change allows multiple sites running off the same code base to each use different configurations of Authboss. To migrate
your code simply use authboss.New() to get an instance of Authboss and all the old things that used to be in the authboss package are
now there. See [this commit to the sample](https://github.com/aarondl/authboss-sample/commit/eea55fc3b03855d4e9fb63577d72ce8ff0cd4079)
to see precisely how to make these changes.
