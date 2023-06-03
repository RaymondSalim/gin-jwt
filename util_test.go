package ssw_go_jwt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const accessTokenPrivateKeyPath = "./Certificates/access_token_jwt_RS256.key"
const accessTokenPublicKeyPath = "./Certificates/access_token_jwt_RS256.key.pub"
const refreshTokenPrivateKeyPath = "./Certificates/refresh_token_jwt_RS256.key"
const refreshTokenPublicKeyPath = "./Certificates/refresh_token_jwt_RS256.key.pub"

const accessTokenPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`
const accessTokenPublicKey = `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvfkiH6dPIZ12oJSwgT22
NgluujyojM/bplnxBGTaHQ3nOqzrCAl6Rt4qDQtzgVvZJcIvrQpsgvv+DP2TH7g5
T83KQSJmOiUs0ZoJQ3mje/12sDIN5hfe9WVhla6skZ3ptbVi00xM22YYzYo3xALC
gaLsHcrBQFnQ9ag0a8C6ZV5NZbJvGYdxpirMocxSrmGQ9UeEFrg/fbBuETKhdEaV
i22BlYIj5B6EW9N0kK1p+sQg/3pyJcfi0fv47XurKfWJw508kmrDF2xxLXe7IeJ8
VvS4CYzsPZpBye6BuXvcw8OHN+m8rPs/VAzsvTOA9OKGUlOJ3EK3jL4tX/kWexb0
sa4+1PnclhqW3Rfieb9QJvl0Ap7EE6VN4vpb/7BRSaFrDdrtkn8Cvr8gDvb6xneF
BTxAN37yoSIF/GDP+MPSsPl0f+OFkNcsia0Kn5BAmMObxyJKmgFW0Lc7XVaTOZpo
KVfRGAUwhCRFDXc2jXwn1+VlICcKcZJxs+m0EQfYnD2w7f9IGoFGb0hyFk94+cgt
fsrzxnvWxrdCnWY52hxU5OlC2XZMMc0NVFu48QMclHSb06VfAEBgPMmM/mKjbB1/
/mJCczwytwBZ/22/ksL3MCaRgzK4gSf34ZZ0eopkDYxH+CBT4gm1pcPXlBL3dahw
3ln9pHtnCuoQVlFA6PHqq+0CAwEAAQ==
-----END PUBLIC KEY-----
`
const refreshTokenPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`
const refreshTokenPublicKey = `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyPo2H4t9ZY5dzbzq4m5+
RjF6Rqqs3zdaFuYQZCQCB3XT6nqM4pdqtJSBMFbtTPYiqW9aRjaGNBPuR573ceuC
Rg0SU0uK32057Na2Hl/rVqPWG7LODLAk0XTEBMwsb5lMFK5U4h0gA9FaE/w1Ai6s
vztotFnncGm3wZ6QiEdu+yrDfje8EytAe/Pea07T6refIJkQxtxouEKRftHu0pIa
ukDWC1jVU5Q5EjNEZ8UYdpyGWh47sSfBCcGw7GGVspBYlNZA9LHMQLjroMKA5eR4
6a3Lm3c22U1aUmadzdAnGdwAhlsC5NkStX2C+a6ek/wqg0rLLKDqUDBMG7aBbHSF
oeAgeyjSWOj5mH5XlaAsAqSDaoI8RZWmDaM3Yvj1F+0dGky/az1ZeJWVpUAFh22W
Dz9I7TIMNo6/OHCOp2WIKTT4JckH+P8kx97YjA4K9XrDzENOGLNMcgP8pX2xOA3H
5k7xsmM3TI1pZOPu7s9pkj3cQR1vUqpbuy9+DKsOyHi45yc/d/lDVJK+6mntUKY0
hdFYFoqI15EQBs2qDbLHCL/qsf1LQHe1OQiWX6ZjSOP0FlAePJt9wkAq8CTOXDSQ
PVC+oPbfe0zuL4oDKkaoXy+8Wc1tTGEeoIhVOOVTxiqAEv0bYGrVUBCtZ3hG1UWI
PxZ5c/z7F+txr1irJ0GTdq0CAwEAAQ==
-----END PUBLIC KEY-----
`

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
					PrivateKeyPath: accessTokenPrivateKeyPath,
					PublicKeyPath:  accessTokenPublicKeyPath,
				},
				RefreshToken: TokenKeysPath{
					PrivateKeyPath: refreshTokenPrivateKeyPath,
					PublicKeyPath:  refreshTokenPublicKeyPath,
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
					PrivateKeyPath: accessTokenPrivateKeyPath,
					PublicKeyPath:  accessTokenPublicKeyPath,
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
					PrivateKeyPath: refreshTokenPrivateKeyPath,
					PublicKeyPath:  refreshTokenPublicKeyPath,
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
					PrivateKeyPath: accessTokenPrivateKeyPath,
				},
				RefreshToken: TokenKeysPath{
					PrivateKeyPath: refreshTokenPrivateKeyPath,
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
					PublicKeyPath: accessTokenPublicKeyPath,
				},
				RefreshToken: TokenKeysPath{
					PublicKeyPath: refreshTokenPublicKeyPath,
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

func TestLoadKeysFromString(t *testing.T) {
	tests := []struct {
		name   string
		params KeyStrings
		assert func(t *testing.T, resp Keys, err error)
	}{
		{
			name: "Success_Load_All",
			params: KeyStrings{
				AccessToken: TokenKeysString{
					PrivateKeyString: accessTokenPrivateKey,
					PublicKeyString:  accessTokenPublicKey,
				},
				RefreshToken: TokenKeysString{
					PrivateKeyString: refreshTokenPrivateKey,
					PublicKeyString:  refreshTokenPublicKey,
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
			params: KeyStrings{
				AccessToken: TokenKeysString{
					PrivateKeyString: accessTokenPrivateKey,
					PublicKeyString:  accessTokenPublicKey,
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
			params: KeyStrings{
				RefreshToken: TokenKeysString{
					PrivateKeyString: refreshTokenPrivateKey,
					PublicKeyString:  refreshTokenPublicKey,
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
			params: KeyStrings{
				AccessToken: TokenKeysString{
					PrivateKeyString: accessTokenPrivateKey,
				},
				RefreshToken: TokenKeysString{
					PrivateKeyString: refreshTokenPrivateKey,
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
			params: KeyStrings{
				AccessToken: TokenKeysString{
					PublicKeyString: accessTokenPublicKey,
				},
				RefreshToken: TokenKeysString{
					PublicKeyString: refreshTokenPublicKey,
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
			k, err := LoadKeysFromString(tt.params)

			tt.assert(t, k, err)
		})
	}
}
