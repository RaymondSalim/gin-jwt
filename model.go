package ssw_go_jwt

import "github.com/golang-jwt/jwt/v5"

type JWTConfig struct {
	SigningAlgorithm           string
	AccessTokenPrivateKeyFile  string
	AccessTokenPublicKeyFile   string
	RefreshTokenPrivateKeyFile string
	RefreshTokenPublicKeyFile  string

	AccessTokenMaxAge  uint32
	RefreshTokenMaxAge uint32

	Issuer             string
	AccessTokenSecret  string
	RefreshTokenSecret string
}

type JWTClaims struct {
	CustomClaims jwt.MapClaims `json:"data,omitempty"`
	jwt.RegisteredClaims
}

type Tokens struct {
	AccessToken  string
	RefreshToken string
}

type TokenType int
