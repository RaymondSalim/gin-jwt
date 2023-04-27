package ssw_go_jwt

//go:generate mockery --name SSWGoJWT --inpackage

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

	validateConfig() error
	getSigningKeyOrSecret(tokenType TokenType) interface{}
	getKeyFunc(tokenType TokenType) func(token *jwt.Token) (interface{}, error)
	generateToken(claims map[string]interface{}, expiresAt time.Time, signingKeyOrSecret interface{}) (string, error)
}

type sswGoJWT struct {
	Config JWTConfig

	initialized   bool
	mode          Mode
	signingMethod jwt.SigningMethod

	accessTokenSigningKey  *rsa.PrivateKey
	accessTokenVerifyKey   *rsa.PublicKey
	refreshTokenSigningKey *rsa.PrivateKey
	refreshTokenVerifyKey  *rsa.PublicKey

	accessTokenSecret  []byte
	refreshTokenSecret []byte
}

// NewGoJWT returns interface SSWGoJWT.
// The returned interface requires to be initialized by calling Init() before any other function.
func NewGoJWT(config JWTConfig) SSWGoJWT {
	return &sswGoJWT{
		Config: config,
	}
}

// Init validates the config passed at NewGoJWT.
// After successful validation, Init will load necessary certificate files if required.
//
// Init returns four possible errors if validation fails; InvalidSigningAlgorithm, MissingSecret, MissingKeyFile, InvalidKeyFilePath
func (g *sswGoJWT) Init() error {
	err := g.validateConfig()
	if err != nil {
		return fmt.Errorf("[%T] init failed: %w", g, err)
	}

	switch g.Config.SigningAlgorithm {
	case SigningAlgorithmRS256:
		g.signingMethod = jwt.SigningMethodRS256
		g.mode = ModeValidationOnly

		if g.Config.AccessTokenPrivateKeyFile != "" && g.Config.RefreshTokenPrivateKeyFile != "" {
			g.mode = ModeFull

			atPrivateKeyData, err := os.ReadFile(g.Config.AccessTokenPrivateKeyFile)
			if err != nil {
				return InvalidKeyFilePath
			}
			atSignKey, err := jwt.ParseRSAPrivateKeyFromPEM(atPrivateKeyData)
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

			g.accessTokenSigningKey = atSignKey
			g.refreshTokenSigningKey = rtSignKey
		}

		atPublicKeyData, err := os.ReadFile(g.Config.AccessTokenPublicKeyFile)
		if err != nil {
			return InvalidKeyFilePath
		}
		atVerifyKey, err := jwt.ParseRSAPublicKeyFromPEM(atPublicKeyData)
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

		g.accessTokenVerifyKey = atVerifyKey
		g.refreshTokenVerifyKey = rtVerifyKey

	case SigningAlgorithmHS256:
		g.signingMethod = jwt.SigningMethodHS256
		g.accessTokenSecret = []byte(g.Config.AccessTokenSecret)
		g.refreshTokenSecret = []byte(g.Config.RefreshTokenSecret)
	}

	g.initialized = true
	return nil
}

func (g *sswGoJWT) validateConfig() error {
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
		if cfg.AccessTokenPublicKeyFile == "" || cfg.RefreshTokenPublicKeyFile == "" {
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

// GenerateTokens generates both access and refresh token.
// The expiry of the tokens depend on the JWTConfig.AccessTokenMaxAge and JWTConfig.RefreshTokenMaxAge value set in the config.
// It is calculated by using adding time.Now and the max age.
//
// GenerateTokens returns ErrorNotInitialized if Init has not been called, else returns errors listed in the go-jwt package
func (g *sswGoJWT) GenerateTokens(claims map[string]interface{}) (Tokens, error) {
	var tokens Tokens
	if !g.initialized {
		return tokens, ErrorNotInitialized
	}
	if g.mode == ModeValidationOnly {
		return tokens, ErrorValidationOnly
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

// ValidateToken validates the given signedToken, using the key/secret provided at NewGoJWT, and using the TokenType passed in the second parameter.
//
// ValidateToken returns ErrorNotInitialized if Init has not been called, else returns errors listed in the go-jwt package
func (g *sswGoJWT) ValidateToken(signedToken string, tokenType TokenType) error {
	if !g.initialized {
		return ErrorNotInitialized
	}

	token, err := jwt.Parse(signedToken, g.getKeyFunc(tokenType))

	if err != nil || !token.Valid {
		return fmt.Errorf("[%T] validate token failed: %w", g, err)
	}

	return nil
}

// ValidateAccessTokenWithClaims validates the given signedToken, using the key/secret provided at NewGoJWT.
// The claims in the JWT Token will be written to the *jwt.MapClaims passed as the second parameter.
//
// ValidateAccessTokenWithClaims returns ErrorNotInitialized if Init has not been called, else returns errors listed in the go-jwt package
func (g *sswGoJWT) ValidateAccessTokenWithClaims(signedToken string, target *jwt.MapClaims) error {
	if !g.initialized {
		return ErrorNotInitialized
	}

	token, err := jwt.ParseWithClaims(signedToken, &jwt.MapClaims{}, g.getKeyFunc(AccessToken))

	if !token.Valid && !errors.Is(err, jwt.ErrTokenExpired) {
		return err
	}

	if claims, ok := token.Claims.(*jwt.MapClaims); ok {
		*target = *claims
	}

	if err != nil {
		return err
	}

	return nil
}

// RenewToken renews the Tokens, as long as the tokens are valid, and the refresh token has not expired
//
// RenewToken returns ErrorNotInitialized if Init has not been called, ErrorRefreshTokenExpired if refresh token has expired, else returns errors listed in the go-jwt package
func (g *sswGoJWT) RenewToken(signedTokens Tokens) (Tokens, error) {
	var tokens Tokens
	if !g.initialized {
		return tokens, ErrorNotInitialized
	}
	if g.mode == ModeValidationOnly {
		return tokens, ErrorValidationOnly
	}

	err := g.ValidateToken(signedTokens.RefreshToken, RefreshToken)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return tokens, ErrorRefreshTokenExpired
		}
		return tokens, fmt.Errorf("[%T] renew token failed: %w", g, err)
	}

	var claims jwt.MapClaims

	err = g.ValidateAccessTokenWithClaims(signedTokens.AccessToken, &claims)
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return tokens, fmt.Errorf("[%T] renew token failed: %w", g, err)
	}

	return g.GenerateTokens(claims)
}
