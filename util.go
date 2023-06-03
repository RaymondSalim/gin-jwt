package ssw_go_jwt

import (
	"crypto/rsa"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
)

type TokenKeysPath struct {
	PrivateKeyPath string
	PublicKeyPath  string
}

type KeyFilePaths struct {
	AccessToken  TokenKeysPath
	RefreshToken TokenKeysPath
}

type TokenKeys struct {
	*rsa.PrivateKey
	*rsa.PublicKey
}

type Keys struct {
	AccessToken  TokenKeys
	RefreshToken TokenKeys
}

func LoadKeysFromFile(p KeyFilePaths) (Keys, error) {
	var keys Keys
	if p.AccessToken.PrivateKeyPath != "" {
		atPrivateKeyData, err := os.ReadFile(p.AccessToken.PrivateKeyPath)
		if err != nil {
			return keys, InvalidKeyFilePath
		}
		atSignKey, err := jwt.ParseRSAPrivateKeyFromPEM(atPrivateKeyData)
		if err != nil {
			return keys, fmt.Errorf("parse RSAPrivateKey failed with error: %w", err)
		}
		keys.AccessToken.PrivateKey = atSignKey
	}

	if p.RefreshToken.PrivateKeyPath != "" {
		rtPrivateKeyData, err := os.ReadFile(p.RefreshToken.PrivateKeyPath)
		if err != nil {
			return keys, InvalidKeyFilePath
		}
		rtSignKey, err := jwt.ParseRSAPrivateKeyFromPEM(rtPrivateKeyData)
		if err != nil {
			return keys, fmt.Errorf("parse RSAPrivateKey failed with error: %w", err)
		}
		keys.RefreshToken.PrivateKey = rtSignKey
	}

	if p.AccessToken.PublicKeyPath != "" {
		atPublicKeyData, err := os.ReadFile(p.AccessToken.PublicKeyPath)
		if err != nil {
			return keys, InvalidKeyFilePath
		}
		atSignKey, err := jwt.ParseRSAPublicKeyFromPEM(atPublicKeyData)
		if err != nil {
			return keys, fmt.Errorf("parse RSAPublicKey failed with error: %w", err)
		}
		keys.AccessToken.PublicKey = atSignKey
	}

	if p.RefreshToken.PublicKeyPath != "" {
		rtPublicKeyData, err := os.ReadFile(p.RefreshToken.PublicKeyPath)
		if err != nil {
			return keys, InvalidKeyFilePath
		}
		rtSignKey, err := jwt.ParseRSAPublicKeyFromPEM(rtPublicKeyData)
		if err != nil {
			return keys, fmt.Errorf("parse RSAPublicKey failed with error: %w", err)
		}
		keys.RefreshToken.PublicKey = rtSignKey
	}

	return keys, nil
}
