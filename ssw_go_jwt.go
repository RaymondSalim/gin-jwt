package ssw_go_jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"time"
)

var (
	timeNow = time.Now
)

type SSWGoJWT interface {
	Init() error

	GenerateTokens(claims map[string]interface{}) (Tokens, error)
	ValidateToken(signedToken string, tokenType TokenType) error
	ValidateAccessTokenWithClaims(signedToken string, target *jwt.MapClaims) error
	RenewToken(signedTokens Tokens) (Tokens, error)

	verifyConfig() error
	getSigningKeyOrSecret(tokenType TokenType) interface{}
	getKeyFunc(tokenType TokenType) func(token *jwt.Token) (interface{}, error)
	generateToken(claims map[string]interface{}, expiresAt time.Time, signingKeyOrSecret interface{}) (string, error)
}

type sswGoJWT struct {
	Config JWTConfig

	initialized   bool
	signingMethod jwt.SigningMethod

	accessTokenSigningKey  *rsa.PrivateKey
	accessTokenVerifyKey   *rsa.PublicKey
	refreshTokenSigningKey *rsa.PrivateKey
	refreshTokenVerifyKey  *rsa.PublicKey

	accessTokenSecret  []byte
	refreshTokenSecret []byte
}

func NewGoJWT(config JWTConfig) SSWGoJWT {
	return &sswGoJWT{
		Config: config,
	}
}

func (g *sswGoJWT) Init() error {
	err := g.verifyConfig()
	if err != nil {
		return fmt.Errorf("[%T] init failed: %w", g, err)
	}

	switch g.Config.SigningAlgorithm {
	case SigningAlgorithmRS256:
		g.signingMethod = jwt.SigningMethodRS256

		atPrivateKeyData, err := os.ReadFile(g.Config.AccessTokenPrivateKeyFile)
		if err != nil {
			return InvalidKeyFilePath
		}
		atSignKey, err := jwt.ParseRSAPrivateKeyFromPEM(atPrivateKeyData)
		if err != nil {
			return fmt.Errorf("[%T] init failed: %w", g, err)
		}

		atPublicKeyData, err := os.ReadFile(g.Config.AccessTokenPublicKeyFile)
		if err != nil {
			return InvalidKeyFilePath
		}
		atVerifyKey, err := jwt.ParseRSAPublicKeyFromPEM(atPublicKeyData)
		if err != nil {
			return fmt.Errorf("[%T] init failed: %w", g, err)
		}

		rtPrivateKeyData, err := os.ReadFile(g.Config.RefreshTokenPrivateKeyFile)
		if err != nil {
			return InvalidKeyFilePath
		}
		rtSignKey, err := jwt.ParseRSAPrivateKeyFromPEM(rtPrivateKeyData)
		if err != nil {
			return fmt.Errorf("[%T] init failed: %w", g, err)
		}

		rtPublicKeyData, err := os.ReadFile(g.Config.RefreshTokenPublicKeyFile)
		if err != nil {
			return InvalidKeyFilePath
		}
		rtVerifyKey, err := jwt.ParseRSAPublicKeyFromPEM(rtPublicKeyData)
		if err != nil {
			return fmt.Errorf("[%T] init failed: %w", g, err)
		}

		g.accessTokenSigningKey = atSignKey
		g.accessTokenVerifyKey = atVerifyKey

		g.refreshTokenSigningKey = rtSignKey
		g.refreshTokenVerifyKey = rtVerifyKey

	case SigningAlgorithmHS256:
		g.signingMethod = jwt.SigningMethodHS256
		g.accessTokenSecret = []byte(g.Config.AccessTokenSecret)
		g.refreshTokenSecret = []byte(g.Config.RefreshTokenSecret)
	}

	g.initialized = true
	return nil
}

func (g *sswGoJWT) verifyConfig() error {
	cfg := g.Config

	if cfg.SigningAlgorithm != SigningAlgorithmRS256 && cfg.SigningAlgorithm != SigningAlgorithmHS256 {
		return InvalidSigningAlgorithm
	}

	if cfg.SigningAlgorithm == SigningAlgorithmHS256 {
		if cfg.AccessTokenSecret == "" || cfg.RefreshTokenSecret == "" {
			return MissingSecret
		}
	}

	if cfg.SigningAlgorithm == SigningAlgorithmRS256 {
		if cfg.AccessTokenPrivateKeyFile == "" ||
			cfg.AccessTokenPublicKeyFile == "" ||
			cfg.RefreshTokenPrivateKeyFile == "" ||
			cfg.RefreshTokenPublicKeyFile == "" {
			return MissingKeyFile
		}
	}

	return nil
}

func (g *sswGoJWT) getSigningKeyOrSecret(tokenType TokenType) interface{} {
	switch g.signingMethod {
	case jwt.SigningMethodHS256:
		if tokenType == AccessToken {
			return g.accessTokenSecret
		} else if tokenType == RefreshToken {
			return g.refreshTokenSecret
		}
	case jwt.SigningMethodRS256:
		if tokenType == AccessToken {
			return g.accessTokenSigningKey
		} else if tokenType == RefreshToken {
			return g.refreshTokenSigningKey
		}
	}

	return nil
}

func (g *sswGoJWT) getKeyFunc(tokenType TokenType) func(token *jwt.Token) (interface{}, error) {
	switch g.signingMethod {
	case jwt.SigningMethodHS256:
		return func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			if tokenType == AccessToken {
				return g.accessTokenSecret, nil
			}

			return g.refreshTokenSecret, nil
		}
	case jwt.SigningMethodRS256:
		return func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			if tokenType == AccessToken {
				return g.accessTokenVerifyKey, nil
			}
			return g.refreshTokenVerifyKey, nil
		}
	}
	return nil
}

func (g *sswGoJWT) generateToken(claims map[string]interface{}, expiresAt time.Time, signingKeyOrSecret interface{}) (string, error) {
	cl := jwt.MapClaims{}
	for k, el := range claims {
		cl[k] = el
	}

	cl["iss"] = g.Config.Issuer
	cl["exp"] = jwt.NewNumericDate(expiresAt)
	cl["iat"] = jwt.NewNumericDate(timeNow())

	token := jwt.NewWithClaims(g.signingMethod, cl)

	signedToken, err := token.SignedString(signingKeyOrSecret)
	if err != nil {
		return "", fmt.Errorf("[%T] generate token failed: %w", g, err)
	}

	return signedToken, nil
}

func (g *sswGoJWT) GenerateTokens(claims map[string]interface{}) (Tokens, error) {
	var tokens Tokens
	if !g.initialized {
		return tokens, ErrorNotInitialized
	}

	accessToken, err := g.generateToken(claims, timeNow().Add(time.Second*time.Duration(g.Config.AccessTokenMaxAge)), g.getSigningKeyOrSecret(AccessToken))
	if err != nil {
		return tokens, err
	}

	refreshToken, err := g.generateToken(nil, timeNow().Add(time.Second*time.Duration(g.Config.RefreshTokenMaxAge)), g.getSigningKeyOrSecret(RefreshToken))
	if err != nil {
		return tokens, err
	}

	tokens.AccessToken = accessToken
	tokens.RefreshToken = refreshToken

	return tokens, nil
}

func (g *sswGoJWT) ValidateToken(signedToken string, tokenType TokenType) error {
	if !g.initialized {
		return ErrorNotInitialized
	}

	token, err := jwt.Parse(signedToken, g.getKeyFunc(tokenType))

	if !token.Valid {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return ErrorTokenExpired
		}
		return ErrorUnauthorized
	}

	// Redundant, just in case
	if err != nil {
		return fmt.Errorf("[%T] validate token failed: %w", g, err)
	}

	return nil
}

func (g *sswGoJWT) ValidateAccessTokenWithClaims(signedToken string, target *jwt.MapClaims) error {
	if !g.initialized {
		return ErrorNotInitialized
	}

	token, err := jwt.ParseWithClaims(signedToken, &jwt.MapClaims{}, g.getKeyFunc(AccessToken))

	if !token.Valid && !errors.Is(err, jwt.ErrTokenExpired) {
		return ErrorUnauthorized
	}

	if claims, ok := token.Claims.(*jwt.MapClaims); ok {
		*target = *claims
	}

	if errors.Is(err, jwt.ErrTokenExpired) {
		return ErrorTokenExpired
	}

	return nil
}

func (g *sswGoJWT) RenewToken(signedTokens Tokens) (Tokens, error) {
	var tokens Tokens
	if !g.initialized {
		return tokens, ErrorNotInitialized
	}

	err := g.ValidateToken(signedTokens.RefreshToken, RefreshToken)
	if err != nil {
		if errors.Is(err, ErrorTokenExpired) {
			return tokens, ErrorRefreshTokenExpired
		}
		return tokens, fmt.Errorf("[%T] renew token failed: %w", g, err)
	}

	var claims jwt.MapClaims

	err = g.ValidateAccessTokenWithClaims(signedTokens.AccessToken, &claims)
	if err != nil && !errors.Is(err, ErrorTokenExpired) {
		return tokens, fmt.Errorf("[%T] renew token failed: %w", g, err)
	}

	return g.GenerateTokens(claims)
}
