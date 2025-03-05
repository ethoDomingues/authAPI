package authAPI

import (
	"github.com/ethoDomingues/braza"
)

var routes = []*braza.Route{
	// login => /login
	{
		Url:         "/login",
		Name:        "login",
		Middlewares: []braza.Func{authNotUser},
		MapCtrl: braza.MapCtrl{
			"POST": &braza.Meth{
				Func:   login,
				Schema: &LoginSchema{},
			},
			"DELETE": &braza.Meth{
				Func: logout,
			},
		},
	},
	// register => /register
	{
		Url:         "/register",
		Name:        "register",
		Middlewares: []braza.Func{authNotUser},
		MapCtrl: braza.MapCtrl{
			"POST": &braza.Meth{
				Func:   register,
				Schema: &RegisterSchema{},
			},
		},
	},
	// whoami => /whoami
	{
		Url:         "/whoami",
		Name:        "whoami",
		Middlewares: []braza.Func{authenticated},
		MapCtrl: braza.MapCtrl{
			"GET": &braza.Meth{
				Func:   whoami,
				Schema: &TknSchema{},
			},
		},
	},
	// checkToken => /check-token
	{
		Url:         "/check-token",
		Name:        "checkToken",
		Middlewares: []braza.Func{authedNoAuthApp},
		MapCtrl: braza.MapCtrl{
			"GET": &braza.Meth{
				Func:   checkAuthTokenHandler,
				Schema: &TknSchema{},
			},
		},
	},
	// registerApp => /new-app
	{
		Url:         "/new-app",
		Name:        "newApp",
		Middlewares: []braza.Func{authedAuthApp},
		Func:        registerApp,
	},
	//  getApp => /get-app
	{
		Url:         "/get-app",
		Name:        "getApp",
		Middlewares: []braza.Func{authedAuthApp},
		MapCtrl: braza.MapCtrl{
			"GET": &braza.Meth{
				Func:   getApp,
				Schema: &GetAppSchema{},
			},
		},
	},
	//  allowApp => /allow-app
	{
		Url:         "/allow-app",
		Name:        "allowApp",
		Middlewares: []braza.Func{authedAuthApp},
		MapCtrl: braza.MapCtrl{
			"POST": &braza.Meth{
				Func:   allowApp,
				Schema: &AllowAppSchema{},
			},
			"DELETE": &braza.Meth{
				Func:   deniApp,
				Schema: &DeniAppSchema{},
			},
		},
	},
	//  loginApp => /login-app
	{
		Url:         "/login-app",
		Name:        "loginApp",
		Middlewares: []braza.Func{authedAuthApp},
		MapCtrl: braza.MapCtrl{
			"POST": &braza.Meth{
				Func:   loginApp,
				Schema: &LoginAppSchema{},
			},
			"DELETE": &braza.Meth{
				Func:   logoutApp,
				Schema: &LogoutAppSchema{},
			},
		},
	},
}
