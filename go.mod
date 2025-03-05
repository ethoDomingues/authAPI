module github.com/ethoDomingues/authAPI

go 1.22.2

replace github.com/ethoDomingues/braza => ../braza

require (
	github.com/ethoDomingues/braza v0.0.0-00010101000000-000000000000
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/google/uuid v1.6.0
	golang.org/x/crypto v0.22.0
	gorm.io/driver/sqlite v1.5.5
	gorm.io/gorm v1.25.9
)

require (
	github.com/ethoDomingues/c3po v0.0.0-20240407180005-a2f0a7e9b4ea // indirect
	github.com/gorilla/websocket v1.5.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/mattn/go-sqlite3 v1.14.17 // indirect
	golang.org/x/net v0.21.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
