package models

import (
	"crypto/rsa"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type History struct {
	Model
	Keep     bool
	Expires  time.Time
	AppUUID  string
	UserUUID string
}

func (h *History) Sign(key *rsa.PrivateKey) string {
	DBSession().Save(h)
	claims := jwt.MapClaims{
		"exp":  h.Expires.UTC().Unix(),
		"app":  h.AppUUID,
		"aud":  h.UUID,
		"user": h.UserUUID,
		"iat":  h.CreatedAt.UTC().Unix(),
	}

	tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	sig, err := tkn.SignedString(key)
	if err != nil {
		log.Println(err)
		return ""
	}
	return sig
}

func (h *History) Validate(app, userAgent string) bool {
	if time.Now().After(h.Expires) {
		DBSession().Delete(h)
		return false
	}
	return h.AppUUID == app
}
