# Integration Requirements

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

