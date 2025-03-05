package models

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/ethoDomingues/authAPI/security"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

type AuthApp struct {
	Model
	Host   string // example.com
	Name   string
	User   string
	Token  string
	PubKey []byte `braza:"-" json:"-" c3po:"-"`
	PriKey []byte `braza:"-" json:"-" c3po:"-"`
}

func (a *AuthApp) ToMap() map[string]any {
	return map[string]any{
		"host":    a.Host,
		"name":    a.Name,
		"user":    a.User,
		"uuid":    a.UUID,
		"token":   a.Token,
		"pub.pem": string(a.PubKey),
	}
}

func (a *AuthApp) ToJson() any {
	return a.ToMap()
}

func (a *AuthApp) AfterCreate(db *gorm.DB) error {
	a.genKeys(db)
	a.UpdateToken(db)
	return nil
}

func (a *AuthApp) genKeys(db *gorm.DB) error {
	if len(a.PriKey) > 0 {
		return nil
	}

	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return err
	}

	pub := &key.PublicKey
	a.PriKey = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	a.PubKey = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub),
		},
	)
	db.Save(a)

	return nil
}

func (a *AuthApp) UpdateToken(db *gorm.DB) error {
	j := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 4464).UTC().Unix(), // 6 meses
	})
	priv, err := security.BytesToPrivKey(a.PriKey)
	if err != nil {
		return err
	}

	t, err := j.SignedString(priv)
	if err != nil {
		return err
	}
	a.Token = t
	return db.Save(a).Error
}

type AllowedApps struct {
	Model
	App  string
	User string
}
