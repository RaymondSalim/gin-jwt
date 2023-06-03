package ssw_go_jwt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLoadKeysFromFile(t *testing.T) {
	tests := []struct {
		name   string
		params KeyFilePaths
		assert func(t *testing.T, resp Keys, err error)
	}{
		{
			name: "Success_Load_All",
			params: KeyFilePaths{
				AccessToken: TokenKeysPath{
					PrivateKeyPath: "./Certificates/access_token_jwt_RS256.key",
					PublicKeyPath:  "./Certificates/access_token_jwt_RS256.key.pub",
				},
				RefreshToken: TokenKeysPath{
					PrivateKeyPath: "./Certificates/refresh_token_jwt_RS256.key",
					PublicKeyPath:  "./Certificates/refresh_token_jwt_RS256.key.pub",
				},
			},
			assert: func(t *testing.T, resp Keys, err error) {
				assert.NotNil(t, resp.AccessToken.PrivateKey)
				assert.NotNil(t, resp.AccessToken.PublicKey)
				assert.NotNil(t, resp.RefreshToken.PrivateKey)
				assert.NotNil(t, resp.RefreshToken.PublicKey)

				assert.NoError(t, err)
			},
		},
		{
			name: "Success_Load_AccessToken_All",
			params: KeyFilePaths{
				AccessToken: TokenKeysPath{
					PrivateKeyPath: "./Certificates/access_token_jwt_RS256.key",
					PublicKeyPath:  "./Certificates/access_token_jwt_RS256.key.pub",
				},
			},
			assert: func(t *testing.T, resp Keys, err error) {
				assert.NotNil(t, resp.AccessToken.PrivateKey)
				assert.NotNil(t, resp.AccessToken.PublicKey)
				assert.Nil(t, resp.RefreshToken.PrivateKey)
				assert.Nil(t, resp.RefreshToken.PublicKey)

				assert.NoError(t, err)
			},
		},
		{
			name: "Success_Load_RefreshToken_All",
			params: KeyFilePaths{
				RefreshToken: TokenKeysPath{
					PrivateKeyPath: "./Certificates/refresh_token_jwt_RS256.key",
					PublicKeyPath:  "./Certificates/refresh_token_jwt_RS256.key.pub",
				},
			},
			assert: func(t *testing.T, resp Keys, err error) {
				assert.Nil(t, resp.AccessToken.PrivateKey)
				assert.Nil(t, resp.AccessToken.PublicKey)
				assert.NotNil(t, resp.RefreshToken.PrivateKey)
				assert.NotNil(t, resp.RefreshToken.PublicKey)

				assert.NoError(t, err)
			},
		},
		{
			name: "Success_Load_All_PrivateKeys",
			params: KeyFilePaths{
				AccessToken: TokenKeysPath{
					PrivateKeyPath: "./Certificates/access_token_jwt_RS256.key",
				},
				RefreshToken: TokenKeysPath{
					PrivateKeyPath: "./Certificates/refresh_token_jwt_RS256.key",
				},
			},
			assert: func(t *testing.T, resp Keys, err error) {
				assert.NotNil(t, resp.AccessToken.PrivateKey)
				assert.Nil(t, resp.AccessToken.PublicKey)
				assert.NotNil(t, resp.RefreshToken.PrivateKey)
				assert.Nil(t, resp.RefreshToken.PublicKey)

				assert.NoError(t, err)
			},
		},
		{
			name: "Success_Load_All_PublicKeys",
			params: KeyFilePaths{
				AccessToken: TokenKeysPath{
					PublicKeyPath: "./Certificates/access_token_jwt_RS256.key.pub",
				},
				RefreshToken: TokenKeysPath{
					PublicKeyPath: "./Certificates/refresh_token_jwt_RS256.key.pub",
				},
			},
			assert: func(t *testing.T, resp Keys, err error) {
				assert.Nil(t, resp.AccessToken.PrivateKey)
				assert.NotNil(t, resp.AccessToken.PublicKey)
				assert.Nil(t, resp.RefreshToken.PrivateKey)
				assert.NotNil(t, resp.RefreshToken.PublicKey)

				assert.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := LoadKeysFromFile(tt.params)

			tt.assert(t, k, err)
		})
	}
}
