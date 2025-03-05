package models

import (
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Model
	Name,
	Email string
	Pass []byte `json:"-" c3po:"-"`
}

func (u *User) HasPass(pass string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Pass = hash
	return nil
}

func (u *User) CheckPass(pass string) bool {
	return bcrypt.CompareHashAndPassword(u.Pass, []byte(pass)) == nil
}

func (u *User) ToMAP() map[string]any {
	return map[string]any{
		"uuid":  u.UUID,
		"name":  u.Name,
		"email": u.Email,
	}
}
