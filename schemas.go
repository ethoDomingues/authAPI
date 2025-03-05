package authAPI

type LoginSchema struct {
	Keep      bool   `braza:"in=body"`
	Email     string `braza:"name=username,in=auth"`
	Password  string `braza:"in=auth"`
	UserAgent string `braza:"name=User-Agent,in=headers,required"`
}

type RegisterSchema struct {
	Keep      bool   `braza:"in=body"`
	Email     string `braza:"required,in=auth,name=username"`
	Password  string `braza:"required,in=auth,name=password"`
	UserAgent string `braza:"required,in=headers,name=User-Agent"`
	Name      string `braza:"required"`
}

type TknSchema struct {
	UserToken string `braza:"in=headers,name=X-USER-TOKEN"`
	AppTkn    string `braza:"in=headers,name=X-APP-TOKEN"`
	UserAgent string `braza:"in=headers,name=User-Agent"`
}

type NewAppSchema struct {
	Host string
	Name string
}

type GetAppSchema struct {
	App string `braza:"required,in=query"`
}

type AllowAppSchema struct {
	App string `braza:"required"`
}

type DeniAppSchema struct {
	App string `braza:"in=query"`
}

type LoginAppSchema struct {
	App       string `braza:"required"`
	Keep      bool
	UserAgent string `braza:"in=headers,name=User-Agent"`
}

type LogoutAppSchema struct {
	App       string `braza:"required"`
	All       bool
	UserAgent string `braza:"in=headers,name=User-Agent"`
}
