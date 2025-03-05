package authAPI

import (
	"crypto/rsa"
	"strings"
	"time"

	"github.com/ethoDomingues/authAPI/models"
	"github.com/ethoDomingues/authAPI/security"
	"github.com/ethoDomingues/braza"
	"github.com/golang-jwt/jwt"
	"gorm.io/gorm"
)

var (
	jwtParser = &jwt.Parser{
		SkipClaimsValidation: true,
	}
)

func JwtValidate(strToken string, key *rsa.PublicKey) (jwt.MapClaims, error) {
	st := strings.Replace(strToken, "Bearer ", "", 1)
	token, err := jwtParser.Parse(st, func(t *jwt.Token) (any, error) { return key, nil })

	if err != nil {
		return nil, err
	}

	err = token.Claims.Valid()
	if err == nil {
		return token.Claims.(jwt.MapClaims), nil
	}
	return nil, err
}

/*
 */

// if has user from any app
func authenticated(ctx *braza.Ctx) {
	if _, ok := ctx.Global["user"].(*models.User); ok {
		ctx.Next()
	}
	ctx.Unauthorized()
}

// if requestApp is authAPI
func authedAuthApp(ctx *braza.Ctx) {
	if _, ok := ctx.Global["user"].(*models.User); ok {
		authApp := ctx.Global["requester_app"].(*models.AuthApp)
		if authApp.Name == "authAPI" {
			ctx.Next()
		}
		ctx.Forbidden()
	}
	ctx.Unauthorized()
}

// if requestApp not is authAPI
func authedNoAuthApp(ctx *braza.Ctx) {
	if _, ok := ctx.Global["user"].(*models.User); ok {
		authApp := ctx.Global["requester_app"].(*models.AuthApp)
		if authApp.Name != "authAPI" {
			ctx.Next()
		}
		ctx.Forbidden()
	}
	ctx.Unauthorized()
}

// if no has user
func authNotUser(ctx *braza.Ctx) {
	_, ok := ctx.Global["user"].(*models.User)
	if ok {
		ctx.Forbidden()
	}
	ctx.Next()
}

/*
 */

func logout(ctx *braza.Ctx) {
	if hID, ok := ctx.Global["histID"].(string); ok {
		db := ctx.Global["db"].(*gorm.DB)
		db = db.Where("UUID = ?", hID).Delete(&models.History{})
		if db.RowsAffected > 0 {
			ctx.NoContent()
		}
	}
	ctx.BadRequest()
}

func login(ctx *braza.Ctx) {
	sch := ctx.Schema.(*LoginSchema)
	u := &models.User{}
	db := models.DBSession()
	db.Where("Email = ?", sch.Email).Find(u)
	if u.ID > 0 {
		if u.CheckPass(sch.Password) {
			exp := time.Now().Add(time.Hour)
			if sch.Keep {
				ctx.Session.Permanent = true
				exp = time.Now().Add(time.Hour * 24 * 31)
			}

			authApp := &models.AuthApp{}
			db.Where("name = ?", "authAPI").Find(authApp)

			h := &models.History{
				Keep:     sch.Keep,
				Expires:  exp,
				AppUUID:  authApp.UUID,
				UserUUID: u.UUID,
			}
			db.Save(h)
			priv, _ := security.BytesToPrivKey(authApp.PriKey)
			tkn := h.Sign(priv)

			ctx.JSON(map[string]any{
				"token": tkn,
			}, 201)
		}
	}
	ctx.JSON(map[string]any{"error": "email or pass invalid"}, 401)
}

func register(ctx *braza.Ctx) {
	sch := ctx.Schema.(*RegisterSchema)
	u := &models.User{}
	db := models.DBSession()
	db.Where("Email = ?", sch.Email).Find(u)
	if u.ID > 0 {
		ctx.JSON(map[string]any{
			"error": "email.unavaiable",
		}, 400)
	}
	u.Name = sch.Name
	u.Email = sch.Email
	err := u.HasPass(sch.Password)
	if err != nil {
		if err.Error() == "invalid password" {
			ctx.JSON(map[string]any{
				"error": "password.invalid",
			}, 400)
		}
	}
	db.Save(u)
	exp := time.Now().Add(time.Hour)
	if sch.Keep {
		exp = time.Now().Add(time.Hour * 24 * 365)
	}
	authApp := &models.AuthApp{}
	db.Where("name = ?", "authAPI").Find(authApp)

	h := &models.History{
		Model:    models.Model{},
		Keep:     sch.Keep,
		Expires:  exp,
		AppUUID:  authApp.UUID,
		UserUUID: u.UUID,
	}
	db.Save(h)

	priv, _ := security.BytesToPrivKey(authApp.PriKey)
	tkn := h.Sign(priv)
	ctx.JSON(map[string]any{
		"token": tkn,
	}, 201)
}

func whoami(ctx *braza.Ctx) {
	u := ctx.Global["user"].(*models.User)
	ctx.JSON(u.ToMAP(), 200)
}

func checkAuthTokenHandler(ctx *braza.Ctx) {
	// app manda seu proprio token e o token do usuario,
	// o before request valida os dois tokens.
	// essa func só confirma e retorna os dados
	if a, ok := ctx.Global["requester_app"].(*models.AuthApp); ok {
		if a.Name == "authApp" {
			ctx.Unauthorized()
		}

		if u, ok := ctx.Global["user"].(*models.User); ok {
			ctx.JSON(u.ToMAP(), 200)
		}
		ctx.Unauthorized()
	}
	ctx.BadRequest()
}

/*
 */

func getApp(ctx *braza.Ctx) {
	db := models.DBSession()
	sch := ctx.Schema.(*GetAppSchema)
	app := &models.AuthApp{}
	db.Where("uuid = ?", sch.App).Find(app)
	if app.UUID == "" {
		ctx.NotFound()
	}
	allowed := false
	if u, ok := ctx.Global["user"].(*models.User); ok {
		var c int64
		db.Table("allowed_apps").Where("app = ? and user = ?", app.UUID, u.UUID).Count(&c)
		if c > 0 {
			allowed = true
		}
	}
	ctx.JSON(map[string]any{"app": app.ToMap(), "allowed": allowed}, 200)
}

func allowApp(ctx *braza.Ctx) {
	var c int64
	db := models.DBSession()
	sch := ctx.Schema.(*AllowAppSchema)
	user := ctx.Global["user"].(*models.User)
	db.Model(&models.AuthApp{}).Where("uuid = ?", sch.App).Count(&c)
	if c == 0 {
		ctx.BadRequest()
	}

	allowApp := &models.AllowedApps{
		App:  sch.App,
		User: user.UUID,
	}
	db.Save(allowApp)
	ctx.Created()
}

func deniApp(ctx *braza.Ctx) {
	sch := ctx.Schema.(*DeniAppSchema)
	h := &models.AuthApp{}
	db := models.DBSession()
	db.Where("UUID = ?", sch.App).Delete(h)
	ctx.NoContent()
}

func loginApp(ctx *braza.Ctx) {
	db := ctx.Global["db"].(*gorm.DB)
	sch := ctx.Schema.(*LoginAppSchema)
	user := ctx.Global["user"].(*models.User)

	app := &models.AuthApp{}
	db.Where("uuid = ?", sch.App).Find(app)
	if app.UUID == "" {
		ctx.BadRequest()
	}

	allApp := &models.AllowedApps{}
	db.Where("app = ? AND user = ?", sch.App, user.UUID).Find(allApp)
	if allApp.UUID == "" {
		ctx.Forbidden()
	}

	exp := time.Hour
	if sch.Keep {
		exp = time.Hour * 24 * 31
	}

	h := models.History{
		AppUUID:  allApp.App,
		UserUUID: user.UUID,
		Expires:  time.Now().Add(exp),
	}
	db.Save(h)
	priv, _ := security.BytesToPrivKey([]byte(app.PriKey))

	tkn := h.Sign(priv)

	ctx.JSON(map[string]string{
		"token": tkn,
	}, 201)
}

func logoutApp(ctx *braza.Ctx) {
	db := ctx.Global["db"].(*gorm.DB)
	sch := ctx.Schema.(*LogoutAppSchema)
	user := ctx.Global["user"].(*models.User)

	hs := []*models.History{}

	db = db.Where("app = ?", sch.App).
		Where("UserUUID = ?", user.UUID)
	if !sch.All {
		db = db.Where("UserAgent = ?", sch.UserAgent)
	}
	db.Delete(&hs)
	ctx.NoContent()
}

func registerApp(ctx *braza.Ctx) {
	db := ctx.Global["db"].(*gorm.DB)
	sch := ctx.Schema.(*NewAppSchema)

	a := &models.AuthApp{}
	db.Where("name = ? OR host = ?", sch.Name, sch.Host).Find(a)
	if a.UUID != "" {
		ctx.BadRequest()
	}

	user := ctx.Global["user"].(*models.User)

	a.Name = sch.Name
	a.Host = sch.Host
	a.User = user.UUID

	db.Save(a)
	ctx.JSON(a, 201)
}
