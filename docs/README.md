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

### Why use Authboss?

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
