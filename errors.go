package ssw_go_jwt

import "errors"

// Config Error
var (
	InvalidSigningAlgorithm = errors.New("invalid signing algorithm")
	MissingSecret           = errors.New("missing secret")
	MissingKeyFile          = errors.New("missing key file")
	InvalidKeyFilePath      = errors.New("key file does not exist")
)

// Module Error
var (
	ErrorNotInitialized      = errors.New("module not initialized")
	ErrorUnauthorized        = errors.New("unauthorized")
	ErrorRefreshTokenExpired = errors.New("refresh token expired")
	ErrorTokenExpired        = errors.New("token expired")
)
