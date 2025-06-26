// Package register allows for user registration.
package register

import (
	"context"
	"net/http"
	"sort"

	"github.com/friendsofgo/errors"

	"github.com/aarondl/authboss/v3"
)

// Pages
const (
	PageRegister = "register"
)

func init() {
	authboss.RegisterModule("register", &Register{})
}

// Register module.
type Register struct {
	*authboss.Authboss
}

// Init the module.
func (r *Register) Init(ab *authboss.Authboss) (err error) {
	r.Authboss = ab

	if _, ok := ab.Config.Storage.Server.(authboss.CreatingServerStorer); !ok {
		return errors.New("register module activated but storer could not be upgraded to CreatingServerStorer")
	}

	if err := ab.Config.Core.ViewRenderer.Load(PageRegister); err != nil {
		return err
	}

	sort.Strings(ab.Config.Modules.RegisterPreserveFields)

	ab.Config.Core.Router.Get("/register", ab.Config.Core.ErrorHandler.Wrap(r.Get))
	ab.Config.Core.Router.Post("/register", ab.Config.Core.ErrorHandler.Wrap(r.Post))

	return nil
}

// Get the register page
func (r *Register) Get(w http.ResponseWriter, req *http.Request) error {
	return r.Config.Core.Responder.Respond(w, req, http.StatusOK, PageRegister, nil)
}

// Post to the register page
func (r *Register) Post(w http.ResponseWriter, req *http.Request) error {
	logger := r.RequestLogger(req)
	validatable, err := r.Core.BodyReader.Read(PageRegister, req)
	if err != nil {
		return err
	}

	var arbitrary map[string]string
	var preserve map[string]string
	if arb, ok := validatable.(authboss.ArbitraryValuer); ok {
		arbitrary = arb.GetValues()
		preserve = make(map[string]string)

		for k, v := range arbitrary {
			if hasString(r.Config.Modules.RegisterPreserveFields, k) {
				preserve[k] = v
			}
		}
	}

	errs := validatable.Validate()
	if errs != nil {
		logger.Info("registration validation failed")
		data := authboss.HTMLData{
			authboss.DataValidation: authboss.ErrorMap(errs),
		}
		if preserve != nil {
			data[authboss.DataPreserve] = preserve
		}
		return r.Config.Core.Responder.Respond(w, req, http.StatusOK, PageRegister, data)
	}

	// Get values from request
	userVals := authboss.MustHaveUserValues(validatable)
	pid, password := userVals.GetPID(), userVals.GetPassword()

	// Put values into newly created user for storage
	storer := authboss.EnsureCanCreate(r.Config.Storage.Server)
	user := authboss.MustBeAuthable(storer.New(req.Context()))

	pass, err := r.Authboss.Config.Core.Hasher.GenerateHash(password)
	if err != nil {
		return err
	}

	user.PutPID(pid)
	user.PutPassword(pass)

	if arbUser, ok := user.(authboss.ArbitraryUser); ok && arbitrary != nil {
		arbUser.PutArbitrary(arbitrary)
	}

	err = storer.Create(req.Context(), user)
	switch {
	case err == authboss.ErrUserFound:
		logger.Infof("user %s attempted to re-register", pid)
		errs = []error{errors.New(r.Localizef(req.Context(), authboss.TxtUserAlreadyExists))}
		data := authboss.HTMLData{
			authboss.DataValidation: authboss.ErrorMap(errs),
		}
		if preserve != nil {
			data[authboss.DataPreserve] = preserve
		}
		return r.Config.Core.Responder.Respond(w, req, http.StatusOK, PageRegister, data)
	case err != nil:
		return err
	}

	req = req.WithContext(context.WithValue(req.Context(), authboss.CTXKeyUser, user))
	handled, err := r.Events.FireAfter(authboss.EventRegister, w, req)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	// Log the user in, but only if the response wasn't handled previously
	// by a module like confirm.
	authboss.PutSession(w, authboss.SessionKey, pid)

	logger.Infof("registered and logged in user %s", pid)
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		Success:      r.Localizef(req.Context(), authboss.TxtRegisteredAndLoggedIn),
		RedirectPath: r.Config.Paths.RegisterOK,
	}
	return r.Config.Core.Redirector.Redirect(w, req, ro)
}

// hasString checks to see if a sorted (ascending) array of
// strings contains a string
func hasString(arr []string, s string) bool {
	index := sort.SearchStrings(arr, s)
	if index < 0 || index >= len(arr) {
		return false
	}

	return arr[index] == s
}
