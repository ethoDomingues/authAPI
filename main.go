package authAPI

import (
	"net/http"
	"os"
	"strings"

	"github.com/ethoDomingues/authAPI/models"
	"github.com/ethoDomingues/authAPI/security"
	"github.com/ethoDomingues/braza"
	"gorm.io/gorm"
)

func CreateApp(cfg *braza.Config, addrs ...string) *braza.App {
	app := braza.NewApp(cfg)
	app.Name = "auth"
	app.SecretKey = os.Getenv("SECRET_AUTH")
	app.BeforeRequest = beforeRequest

	app.Mount(&braza.Router{
		Name:   "authAPI",
		Prefix: "/v1",
		Routes: routes,
		Cors: &braza.Cors{
			AllowOrigins: []string{"*"},
			AllowHeaders: []string{"*", "Authorization"},
		},
	})

	models.DBSession().AutoMigrate(
		&models.User{},
		&models.AuthApp{},
		&models.History{},
		&models.AllowedApps{},
	)
	addr := ":5443"
	if len(addrs) > 0 {
		addr = addrs[0]
	}

	app.Srv = &http.Server{Addr: addr}
	return app
}

func beforeRequest(ctx *braza.Ctx) {
	db := models.DBSession()
	ctx.Global["db"] = db
	validateRqApp(ctx)
	getUser(ctx)
}

func validateRqApp(ctx *braza.Ctx) {
	db := ctx.Global["db"].(*gorm.DB)

	tkn := ctx.Request.Header.Get("X-App-Token")
	appUUID := ctx.Request.Header.Get("X-App-UUID")

	if tkn == "" && appUUID == "" {
		// if caiu aq, deve ser validado como authAPI
		// if o token não for de authAPI, sera recusado
		authApp := &models.AuthApp{}
		db.Where("name = ?", "authAPI").Find(authApp)
		ctx.Global["isAuthApp"] = true
		ctx.Global["requester_app"] = authApp
		return
	}

	if appUUID == "" || tkn == "" {
		// if caiu aq, ta faltando o token do usuario, ou o app uuid
		ctx.TEXT("field 'X-App-Uuid' is required when 'X-App-Token' is set", 400)
	}
	app := &models.AuthApp{}
	db.Where("uuid = ?", appUUID).Find(app)
	pbk, _ := security.BytesToPubKey(app.PubKey)
	_, err := JwtValidate(tkn, pbk)
	if err == nil {
		// if caiu aq, o token do usuario foi assinado pelo app com o uuid
		ctx.Global["requester_app"] = app
		return
	}
	ctx.Unauthorized()
}

func getUser(ctx *braza.Ctx) {
	db := ctx.Global["db"].(*gorm.DB)
	aud := ""

	strTkn := ctx.Request.Header.Get("X-User-Token")
	if t := ctx.Request.Header.Get("Authorization"); t != "" {
		strTkn = t
	}
	if !strings.HasPrefix(strTkn, "Bearer ") {
		return
	}

	reqApp := ctx.Global["requester_app"].(*models.AuthApp) //

	pbk, _ := security.BytesToPubKey(reqApp.PubKey)
	claims, err := JwtValidate(strTkn, pbk)

	if err == nil {
		aud = claims["aud"].(string)
	} else {
		// if caiu aq, ou o tkn expirou ou não foi assinado pelo app requerinte. (suponhado q foi enviado um tkn)
		ctx.Unauthorized()
	}

	if aud == "" {
		sid := ctx.Session.Get("histID")
		if sid != "" {
			aud = sid
		}
	}

	h := &models.History{}
	db.Where("UUID = ?", aud).Find(h)
	if h.ID > 0 {
		if !h.Validate(reqApp.UUID, ctx.Request.UserAgent()) {
			ctx.Unauthorized() // invalid token: expired or request for other device, etc
		}

		u := &models.User{}
		db.Where("UUID = ?", h.UserUUID).Find(u)
		if u.ID > 0 {
			ctx.Global["user"] = u
			ctx.Global["histID"] = aud
			ctx.Session.Set("histID", h.UUID)
		}
	}
}
