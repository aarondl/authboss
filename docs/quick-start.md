# Quick Start

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
