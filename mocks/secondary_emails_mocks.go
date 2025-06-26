package mocks

import (
	"context"

	"github.com/aarondl/authboss/v3"
)

type UserWithSecondaryEmails struct {
	User
	SecondaryEmails []string
}

// GetSecondaryEmails for the user
func (u *UserWithSecondaryEmails) GetSecondaryEmails() []string {
	return u.SecondaryEmails
}

type ServerStorerWithSecondaryEmails struct {
	BasicStorer *ServerStorer
}

func (s ServerStorerWithSecondaryEmails) Load(ctx context.Context, key string) (authboss.User, error) {
	user, err := s.BasicStorer.Load(ctx, key)
	if err != nil {
		return user, err
	}

	mockedUser := user.(*User)

	return &UserWithSecondaryEmails{
		User:            *mockedUser,
		SecondaryEmails: []string{"personal@one.com", "personal@two.com"},
	}, nil
}

func (s ServerStorerWithSecondaryEmails) Save(ctx context.Context, user authboss.User) error {
	if u, ok := user.(*UserWithSecondaryEmails); ok {
		user = &u.User
	}

	return s.BasicStorer.Save(ctx, user)
}
