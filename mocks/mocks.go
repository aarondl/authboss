// Package mocks defines implemented interfaces for testing modules
package mocks

import (
	"context"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/friendsofgo/errors"
	"github.com/aarondl/authboss/v3"
)

// User represents all possible fields a authboss User may have
type User struct {
	Username           string
	Email              string
	Password           string
	RecoverSelector    string
	RecoverVerifier    string
	RecoverTokenExpiry time.Time
	ConfirmSelector    string
	ConfirmVerifier    string
	Confirmed          bool
	AttemptCount       int
	LastAttempt        time.Time
	Locked             time.Time

	OAuth2UID      string
	OAuth2Provider string
	OAuth2Token    string
	OAuth2Refresh  string
	OAuth2Expiry   time.Time

	OTPs           string
	TOTPSecretKey  string
	TOTPLastCode   string
	SMSPhoneNumber string
	RecoveryCodes  string

	SMSPhoneNumberSeed string

	Arbitrary map[string]string
}

// GetPID from user
func (u User) GetPID() string { return u.Email }

// GetEmail from user
func (u User) GetEmail() string { return u.Email }

// GetUsername from user
func (u User) GetUsername() string { return u.Username }

// GetPassword from user
func (u User) GetPassword() string { return u.Password }

// GetRecoverSelector from user
func (u User) GetRecoverSelector() string { return u.RecoverSelector }

// GetRecoverVerifier from user
func (u User) GetRecoverVerifier() string { return u.RecoverVerifier }

// GetRecoverExpiry from user
func (u User) GetRecoverExpiry() time.Time { return u.RecoverTokenExpiry }

// GetConfirmSelector from user
func (u User) GetConfirmSelector() string { return u.ConfirmSelector }

// GetConfirmVerifier from user
func (u User) GetConfirmVerifier() string { return u.ConfirmVerifier }

// GetConfirmed from user
func (u User) GetConfirmed() bool { return u.Confirmed }

// GetAttemptCount from user
func (u User) GetAttemptCount() int { return u.AttemptCount }

// GetLastAttempt from user
func (u User) GetLastAttempt() time.Time { return u.LastAttempt }

// GetLocked from user
func (u User) GetLocked() time.Time { return u.Locked }

// IsOAuth2User returns true if the user is an oauth2 user
func (u User) IsOAuth2User() bool { return len(u.OAuth2Provider) != 0 }

// GetOAuth2UID from user
func (u User) GetOAuth2UID() string { return u.OAuth2UID }

// GetOAuth2Provider from user
func (u User) GetOAuth2Provider() string { return u.OAuth2Provider }

// GetOAuth2AccessToken from user
func (u User) GetOAuth2AccessToken() string { return u.OAuth2Token }

// GetOAuth2RefreshToken from user
func (u User) GetOAuth2RefreshToken() string { return u.OAuth2Refresh }

// GetOAuth2Expiry from user
func (u User) GetOAuth2Expiry() time.Time { return u.OAuth2Expiry }

// GetArbitrary from user
func (u User) GetArbitrary() map[string]string { return u.Arbitrary }

// GetOTPs from user
func (u User) GetOTPs() string { return u.OTPs }

// GetTOTPSecretKey from user
func (u User) GetTOTPSecretKey() string { return u.TOTPSecretKey }

// GetTOTPLastCode from user
func (u User) GetTOTPLastCode() string { return u.TOTPLastCode }

// GetSMSPhoneNumber from user
func (u User) GetSMSPhoneNumber() string { return u.SMSPhoneNumber }

// GetSMSPhoneNumberSeed from user
func (u User) GetSMSPhoneNumberSeed() string { return u.SMSPhoneNumberSeed }

// GetRecoveryCodes from user
func (u User) GetRecoveryCodes() string { return u.RecoveryCodes }

// PutPID into user
func (u *User) PutPID(email string) { u.Email = email }

// PutUsername into user
func (u *User) PutUsername(username string) { u.Username = username }

// PutEmail into user
func (u *User) PutEmail(email string) { u.Email = email }

// PutPassword into user
func (u *User) PutPassword(password string) { u.Password = password }

// PutRecoverSelector into user
func (u *User) PutRecoverSelector(recoverSelector string) { u.RecoverSelector = recoverSelector }

// PutRecoverVerifier into user
func (u *User) PutRecoverVerifier(recoverVerifier string) { u.RecoverVerifier = recoverVerifier }

// PutRecoverExpiry into user
func (u *User) PutRecoverExpiry(recoverTokenExpiry time.Time) {
	u.RecoverTokenExpiry = recoverTokenExpiry
}

// PutConfirmSelector into user
func (u *User) PutConfirmSelector(confirmSelector string) { u.ConfirmSelector = confirmSelector }

// PutConfirmVerifier into user
func (u *User) PutConfirmVerifier(confirmVerifier string) { u.ConfirmVerifier = confirmVerifier }

// PutConfirmed into user
func (u *User) PutConfirmed(confirmed bool) { u.Confirmed = confirmed }

// PutAttemptCount into user
func (u *User) PutAttemptCount(attemptCount int) { u.AttemptCount = attemptCount }

// PutLastAttempt into user
func (u *User) PutLastAttempt(attemptTime time.Time) { u.LastAttempt = attemptTime }

// PutLocked into user
func (u *User) PutLocked(locked time.Time) { u.Locked = locked }

// PutOAuth2UID into user
func (u *User) PutOAuth2UID(uid string) { u.OAuth2UID = uid }

// PutOAuth2Provider into user
func (u *User) PutOAuth2Provider(provider string) { u.OAuth2Provider = provider }

// PutOAuth2AccessToken into user
func (u *User) PutOAuth2AccessToken(token string) { u.OAuth2Token = token }

// PutOAuth2RefreshToken into user
func (u *User) PutOAuth2RefreshToken(refresh string) { u.OAuth2Refresh = refresh }

// PutOAuth2Expiry into user
func (u *User) PutOAuth2Expiry(expiry time.Time) { u.OAuth2Expiry = expiry }

// PutArbitrary into user
func (u *User) PutArbitrary(arb map[string]string) { u.Arbitrary = arb }

// PutOTPs into user
func (u *User) PutOTPs(otps string) { u.OTPs = otps }

// PutTOTPSecretKey into user
func (u *User) PutTOTPSecretKey(key string) { u.TOTPSecretKey = key }

// PutTOTPLastCode into user
func (u *User) PutTOTPLastCode(key string) { u.TOTPLastCode = key }

// PutSMSPhoneNumber into user
func (u *User) PutSMSPhoneNumber(number string) { u.SMSPhoneNumber = number }

// PutRecoveryCodes into user
func (u *User) PutRecoveryCodes(codes string) { u.RecoveryCodes = codes }

// ServerStorer should be valid for any module storer defined in authboss.
type ServerStorer struct {
	Users    map[string]*User
	RMTokens map[string][]string
}

// NewServerStorer constructor
func NewServerStorer() *ServerStorer {
	return &ServerStorer{
		Users:    make(map[string]*User),
		RMTokens: make(map[string][]string),
	}
}

// New constructs a blank user to later be created
func (s *ServerStorer) New(context.Context) authboss.User {
	return &User{}
}

// Create a user
func (s *ServerStorer) Create(ctx context.Context, user authboss.User) error {
	u := user.(*User)
	if _, ok := s.Users[u.Email]; ok {
		return authboss.ErrUserFound
	}
	s.Users[u.Email] = u
	return nil
}

// Load a user
func (s *ServerStorer) Load(ctx context.Context, key string) (authboss.User, error) {
	user, ok := s.Users[key]
	if ok {
		return user, nil
	}

	return nil, authboss.ErrUserNotFound
}

// Save a user
func (s *ServerStorer) Save(ctx context.Context, user authboss.User) error {
	u := user.(*User)
	if _, ok := s.Users[u.Email]; !ok {
		return authboss.ErrUserNotFound
	}
	s.Users[u.Email] = u
	return nil
}

// NewFromOAuth2 finds a user with the given details, or returns a new one
func (s *ServerStorer) NewFromOAuth2(ctx context.Context, provider string, details map[string]string) (authboss.OAuth2User, error) {
	uid := details["uid"]
	email := details["email"]
	name := details["name"]
	pid := authboss.MakeOAuth2PID(provider, uid)

	u, ok := s.Users[pid]
	if ok {
		u.Username = name
		u.Email = email
		return u, nil
	}

	return &User{
		OAuth2UID:      uid,
		OAuth2Provider: provider,
		Email:          email,
		Username:       name,
	}, nil
}

// SaveOAuth2 creates a user if not found, or updates one that exists.
func (s *ServerStorer) SaveOAuth2(ctx context.Context, user authboss.OAuth2User) error {
	u := user.(*User)

	pid := authboss.MakeOAuth2PID(u.OAuth2Provider, u.OAuth2UID)
	// Since we don't have to differentiate between
	// insert/update in a map, we just overwrite
	s.Users[pid] = u
	return nil
}

// LoadByConfirmSelector finds a user by his confirm selector
func (s *ServerStorer) LoadByConfirmSelector(ctx context.Context, selector string) (authboss.ConfirmableUser, error) {
	for _, v := range s.Users {
		if v.ConfirmSelector == selector {
			return v, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}

// LoadByRecoverSelector finds a user by his recover token
func (s *ServerStorer) LoadByRecoverSelector(ctx context.Context, selector string) (authboss.RecoverableUser, error) {
	for _, v := range s.Users {
		if v.RecoverSelector == selector {
			return v, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}

// AddRememberToken for remember me
func (s *ServerStorer) AddRememberToken(ctx context.Context, key, token string) error {
	arr := s.RMTokens[key]
	s.RMTokens[key] = append(arr, token)
	return nil
}

// DelRememberTokens for a user
func (s *ServerStorer) DelRememberTokens(ctx context.Context, key string) error {
	delete(s.RMTokens, key)
	return nil
}

// UseRememberToken if it exists, deleting it in the process
func (s *ServerStorer) UseRememberToken(ctx context.Context, givenKey, token string) (err error) {
	arr, ok := s.RMTokens[givenKey]
	if !ok {
		return authboss.ErrTokenNotFound
	}

	for i, tok := range arr {
		if tok == token {
			if len(arr) == 1 {
				delete(s.RMTokens, givenKey)
				return nil
			}

			arr[i] = arr[len(arr)-1]
			s.RMTokens[givenKey] = arr[:len(arr)-2]
			return nil
		}
	}

	return authboss.ErrTokenNotFound
}

// FailStorer is used for testing module initialize functions that
// recover more than the base storer
type FailStorer struct {
	User
}

// Create fails
func (FailStorer) Create(context.Context) error {
	return errors.New("fail storer: create")
}

// Save fails
func (FailStorer) Save(context.Context) error {
	return errors.New("fail storer: put")
}

// Load fails
func (FailStorer) Load(context.Context) error {
	return errors.New("fail storer: get")
}

// ClientState is used for testing the client stores on context
type ClientState struct {
	Values        map[string]string
	GetShouldFail bool
}

// NewClientState constructs a ClientStorer
func NewClientState(data ...string) *ClientState {
	if len(data) != 0 && len(data)%2 != 0 {
		panic("It should be a key value list of arguments.")
	}

	values := make(map[string]string)

	for i := 0; i < len(data)-1; i += 2 {
		values[data[i]] = data[i+1]
	}

	return &ClientState{Values: values}
}

// Get a key's value
func (m *ClientState) Get(key string) (string, bool) {
	if m.GetShouldFail {
		return "", false
	}

	v, ok := m.Values[key]
	return v, ok
}

// Put a value
func (m *ClientState) Put(key, val string) { m.Values[key] = val }

// Del a key/value pair
func (m *ClientState) Del(key string) { delete(m.Values, key) }

// ClientStateRW stores things that would originally
// go in a session, or a map, in memory!
type ClientStateRW struct {
	ClientValues map[string]string
}

// NewClientRW takes the data from a client state
// and returns.
func NewClientRW() *ClientStateRW {
	return &ClientStateRW{
		ClientValues: make(map[string]string),
	}
}

// ReadState from memory
func (c *ClientStateRW) ReadState(*http.Request) (authboss.ClientState, error) {
	return &ClientState{Values: c.ClientValues}, nil
}

// WriteState to memory
func (c *ClientStateRW) WriteState(w http.ResponseWriter, cstate authboss.ClientState, cse []authboss.ClientStateEvent) error {
	for _, e := range cse {
		switch e.Kind {
		case authboss.ClientStateEventPut:
			c.ClientValues[e.Key] = e.Value
		case authboss.ClientStateEventDel:
			delete(c.ClientValues, e.Key)
		case authboss.ClientStateEventDelAll:
			c.ClientValues = make(map[string]string)
		}
	}

	return nil
}

// Request returns a new request with optional key-value body (form-post)
func Request(method string, postKeyValues ...string) *http.Request {
	var body io.Reader
	location := "http://localhost"

	if len(postKeyValues) > 0 {
		urlValues := make(url.Values)
		for i := 0; i < len(postKeyValues); i += 2 {
			urlValues.Set(postKeyValues[i], postKeyValues[i+1])
		}

		if method == "POST" || method == "PUT" {
			body = strings.NewReader(urlValues.Encode())
		} else {
			location += "?" + urlValues.Encode()
		}
	}

	req, err := http.NewRequest(method, location, body)
	if err != nil {
		panic(err.Error())
	}

	if len(postKeyValues) > 0 {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	return req
}

// Mailer helps simplify mailer testing by storing the last sent email
type Mailer struct {
	Last    authboss.Email
	SendErr string
}

// NewMailer constructs a  mailer
func NewMailer() *Mailer {
	return &Mailer{}
}

// Send an e-mail
func (m *Mailer) Send(ctx context.Context, email authboss.Email) error {
	if len(m.SendErr) > 0 {
		return errors.New(m.SendErr)
	}

	m.Last = email
	return nil
}

// AfterCallback is a callback that knows if it was called
type AfterCallback struct {
	HasBeenCalled bool
	Fn            authboss.EventHandler
}

// NewAfterCallback constructs a new aftercallback.
func NewAfterCallback() *AfterCallback {
	m := AfterCallback{}

	m.Fn = func(http.ResponseWriter, *http.Request, bool) (bool, error) {
		m.HasBeenCalled = true
		return false, nil
	}

	return &m
}

// Renderer mock
type Renderer struct {
	Pages []string

	// Render call variables
	Context context.Context
	Page    string
	Data    authboss.HTMLData
}

// HasLoadedViews ensures the views were loaded
func (r *Renderer) HasLoadedViews(pages ...string) error {
	if len(r.Pages) != len(pages) {
		return errors.Errorf("want: %d loaded views, got: %d", len(pages), len(r.Pages))
	}

	for i, want := range pages {
		got := r.Pages[i]
		if want != got {
			return errors.Errorf("want: %s [%d], got: %s", want, i, got)
		}
	}

	return nil
}

// Load nothing but store the pages that were loaded
func (r *Renderer) Load(pages ...string) error {
	r.Pages = append(r.Pages, pages...)
	return nil
}

// Render nothing, but record the arguments into the renderer
func (r *Renderer) Render(ctx context.Context, page string, data authboss.HTMLData) ([]byte, string, error) {
	r.Context = ctx
	r.Page = page
	r.Data = data
	return nil, "text/html", nil
}

// Responder records how a request was responded to
type Responder struct {
	Status int
	Page   string
	Data   authboss.HTMLData
}

// Respond stores the arguments in the struct
func (r *Responder) Respond(w http.ResponseWriter, req *http.Request, code int, page string, data authboss.HTMLData) error {
	r.Status = code
	r.Page = page
	r.Data = data

	return nil
}

// Redirector stores the redirect options passed to it and writes the Code
// to the ResponseWriter.
type Redirector struct {
	Options authboss.RedirectOptions
}

// Redirect a request
func (r *Redirector) Redirect(w http.ResponseWriter, req *http.Request, ro authboss.RedirectOptions) error {
	r.Options = ro
	if len(ro.RedirectPath) == 0 {
		panic("no redirect path on redirect call")
	}
	http.Redirect(w, req, ro.RedirectPath, ro.Code)
	return nil
}

// Emailer that holds the options it was given
type Emailer struct {
	Email authboss.Email
}

// Send an e-mail
func (e *Emailer) Send(ctx context.Context, email authboss.Email) error {
	e.Email = email
	return nil
}

// BodyReader reads the body of a request and returns some values
type BodyReader struct {
	Return authboss.Validator
}

// Read the return values
func (b BodyReader) Read(page string, r *http.Request) (authboss.Validator, error) {
	return b.Return, nil
}

// Values is returned from the BodyReader
type Values struct {
	PID         string
	Password    string
	Token       string
	Code        string
	Recovery    string
	PhoneNumber string
	Remember    bool

	Errors []error
}

// GetPID from values
func (v Values) GetPID() string {
	return v.PID
}

// GetPassword from values
func (v Values) GetPassword() string {
	return v.Password
}

// GetToken from values
func (v Values) GetToken() string {
	return v.Token
}

// GetCode from values
func (v Values) GetCode() string {
	return v.Code
}

// GetPhoneNumber from values
func (v Values) GetPhoneNumber() string {
	return v.PhoneNumber
}

// GetRecoveryCode from values
func (v Values) GetRecoveryCode() string {
	return v.Recovery
}

// GetShouldRemember gets the value that tells
// the remember module if it should remember the user
func (v Values) GetShouldRemember() bool {
	return v.Remember
}

// Validate the values
func (v Values) Validate() []error {
	return v.Errors
}

// ArbValues is arbitrary value storage
type ArbValues struct {
	Values map[string]string
	Errors []error
}

// GetPID gets the pid
func (a ArbValues) GetPID() string {
	return a.Values["email"]
}

// GetPassword gets the password
func (a ArbValues) GetPassword() string {
	return a.Values["password"]
}

// GetValues returns all values
func (a ArbValues) GetValues() map[string]string {
	return a.Values
}

// Validate nothing
func (a ArbValues) Validate() []error {
	return a.Errors
}

// Logger logs to the void
type Logger struct {
}

// Info logging
func (l Logger) Info(string) {}

// Error logging
func (l Logger) Error(string) {}

// Router records the routes that were registered
type Router struct {
	Gets    []string
	Posts   []string
	Deletes []string
}

// ServeHTTP does nothing
func (Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
}

// Get records the path in the router
func (r *Router) Get(path string, _ http.Handler) {
	r.Gets = append(r.Gets, path)
}

// Post records the path in the router
func (r *Router) Post(path string, _ http.Handler) {
	r.Posts = append(r.Posts, path)
}

// Delete records the path in the router
func (r *Router) Delete(path string, _ http.Handler) {
	r.Deletes = append(r.Deletes, path)
}

// HasGets ensures all gets routes are present
func (r *Router) HasGets(gets ...string) error {
	return r.hasRoutes(gets, r.Gets)
}

// HasPosts ensures all gets routes are present
func (r *Router) HasPosts(posts ...string) error {
	return r.hasRoutes(posts, r.Posts)
}

// HasDeletes ensures all gets routes are present
func (r *Router) HasDeletes(deletes ...string) error {
	return r.hasRoutes(deletes, r.Deletes)
}

func (r *Router) hasRoutes(want []string, got []string) error {
	if len(got) != len(want) {
		return errors.Errorf("want: %d get routes, got: %d", len(want), len(got))
	}

	for i, w := range want {
		g := got[i]
		if w != g {
			return errors.Errorf("wanted route: %s [%d], but got: %s", w, i, g)
		}
	}

	return nil
}

// ErrorHandler just holds the last error
type ErrorHandler struct {
	Error error
}

// Wrap an http method
func (e *ErrorHandler) Wrap(handler func(w http.ResponseWriter, r *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := handler(w, r); err != nil {
			e.Error = err
		}
	})
}

// Hasher is actually just a normal bcrypt hasher
type Hasher struct{}

func (m Hasher) GenerateHash(s string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func (m Hasher) CompareHashAndPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
