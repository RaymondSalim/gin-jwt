package ssw_go_jwt

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"math/big"
	"strconv"
	"testing"
	"time"
)

const refreshTokenPrivateKeyFile = "./Certificates/refresh_token_jwt_RS256.key"
const refreshTokenPublicKeyFile = "./Certificates/refresh_token_jwt_RS256.key.pub"
const accessTokenPrivateKeyFile = "./Certificates/access_token_jwt_RS256.key"
const accessTokenPublicKeyFile = "./Certificates/access_token_jwt_RS256.key.pub"
const goModFile = "./go.mod"
const secret = "krabby patty's formula"
const testString = "this is a test string"
const testInt = 321

var testClaims = map[string]interface{}{
	"sub":   "1234567890",
	"name":  "John Doe",
	"admin": true,
	"iat":   1516239022,
}

var testTime = time.Unix(1680282501, 0)

func TestGoJWT_NewGoJWT(t *testing.T) {
	test := struct {
		name string
		JWTConfig
		assert func(t *testing.T, resp SSWGoJWT, expected SSWGoJWT)
	}{
		name: "success",
		JWTConfig: JWTConfig{
			SigningAlgorithm:           testString,
			AccessTokenPrivateKeyFile:  testString,
			AccessTokenPublicKeyFile:   testString,
			RefreshTokenPrivateKeyFile: testString,
			RefreshTokenPublicKeyFile:  testString,
			AccessTokenMaxAge:          testInt,
			RefreshTokenMaxAge:         testInt,
			Issuer:                     testString,
			AccessTokenSecret:          testString,
			RefreshTokenSecret:         testString,
		},
		assert: func(t *testing.T, resp SSWGoJWT, expected SSWGoJWT) {
			assert.Equal(t, expected, resp)
		},
	}

	t.Run(test.name, func(t *testing.T) {
		expected := &sswGoJWT{
			Config: test.JWTConfig,
		}

		actual := NewGoJWT(test.JWTConfig)

		test.assert(t, actual, SSWGoJWT(expected))
	})
}

func TestGoJWT_VerifyConfig(t *testing.T) {
	tests := []struct {
		name string
		JWTConfig
		assert func(t *testing.T, resp error)
	}{
		{
			name: "success_rs256",
			JWTConfig: JWTConfig{
				SigningAlgorithm:           SigningAlgorithmRS256,
				AccessTokenPublicKeyFile:   accessTokenPublicKeyFile,
				AccessTokenPrivateKeyFile:  accessTokenPrivateKeyFile,
				RefreshTokenPublicKeyFile:  refreshTokenPublicKeyFile,
				RefreshTokenPrivateKeyFile: refreshTokenPrivateKeyFile,
			},
			assert: func(t *testing.T, resp error) {
				assert.NoError(t, resp)
			},
		},
		{
			name: "success_hs256",
			JWTConfig: JWTConfig{
				SigningAlgorithm:   SigningAlgorithmHS256,
				AccessTokenSecret:  secret,
				RefreshTokenSecret: secret,
			},
			assert: func(t *testing.T, resp error) {
				assert.NoError(t, resp)
			},
		},
		{
			name: "fail_invalid_algorithm",
			JWTConfig: JWTConfig{
				SigningAlgorithm: "very cool algorithm",
			},
			assert: func(t *testing.T, resp error) {
				assert.ErrorIs(t, resp, InvalidSigningAlgorithm)
			},
		},
		{
			name: "fail_hs256_no_access_token_secret",
			JWTConfig: JWTConfig{
				SigningAlgorithm:   SigningAlgorithmHS256,
				RefreshTokenSecret: secret,
			},
			assert: func(t *testing.T, resp error) {
				assert.ErrorIs(t, resp, MissingSecret)
			},
		},
		{
			name: "fail_hs256_no_refresh_token_secret",
			JWTConfig: JWTConfig{
				SigningAlgorithm:  SigningAlgorithmHS256,
				AccessTokenSecret: secret,
			},
			assert: func(t *testing.T, resp error) {
				assert.ErrorIs(t, resp, MissingSecret)
			},
		},
		{
			name: "fail_rs_256_no_access_token_public_key",
			JWTConfig: JWTConfig{
				SigningAlgorithm:           SigningAlgorithmRS256,
				AccessTokenPrivateKeyFile:  accessTokenPrivateKeyFile,
				RefreshTokenPublicKeyFile:  refreshTokenPublicKeyFile,
				RefreshTokenPrivateKeyFile: refreshTokenPrivateKeyFile,
			},
			assert: func(t *testing.T, resp error) {
				assert.ErrorIs(t, resp, MissingKeyFile)
			},
		},
		{
			name: "fail_rs_256_no_refresh_token_public_key",
			JWTConfig: JWTConfig{
				SigningAlgorithm:           SigningAlgorithmRS256,
				AccessTokenPrivateKeyFile:  accessTokenPrivateKeyFile,
				AccessTokenPublicKeyFile:   accessTokenPublicKeyFile,
				RefreshTokenPrivateKeyFile: refreshTokenPrivateKeyFile,
			},
			assert: func(t *testing.T, resp error) {
				assert.ErrorIs(t, resp, MissingKeyFile)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &sswGoJWT{
				Config: tt.JWTConfig,
			}

			resp := g.validateConfig()

			if tt.assert != nil {
				tt.assert(t, resp)
			}
		})
	}
}

func TestGoJWT_Init(t *testing.T) {
	tests := []struct {
		name string
		JWTConfig
		assert func(t *testing.T, resp error, jwt *sswGoJWT)
	}{
		{
			name: "success_rs256_mode_full",
			JWTConfig: JWTConfig{
				SigningAlgorithm:           SigningAlgorithmRS256,
				AccessTokenPublicKeyFile:   accessTokenPublicKeyFile,
				AccessTokenPrivateKeyFile:  accessTokenPrivateKeyFile,
				RefreshTokenPublicKeyFile:  refreshTokenPublicKeyFile,
				RefreshTokenPrivateKeyFile: refreshTokenPrivateKeyFile,
			},
			assert: func(t *testing.T, resp error, jwt *sswGoJWT) {
				assert.NoError(t, resp)

				assert.True(t, jwt.initialized)

				assert.NotNil(t, jwt.accessTokenSigningKey)
				assert.NotNil(t, jwt.accessTokenVerifyKey)
				assert.NotNil(t, jwt.refreshTokenSigningKey)
				assert.NotNil(t, jwt.refreshTokenVerifyKey)

				assert.EqualValues(t, ModeFull, jwt.mode)
			},
		},
		{
			name: "success_rs256_mode_validation_only",
			JWTConfig: JWTConfig{
				SigningAlgorithm:          SigningAlgorithmRS256,
				AccessTokenPublicKeyFile:  accessTokenPublicKeyFile,
				RefreshTokenPublicKeyFile: refreshTokenPublicKeyFile,
			},
			assert: func(t *testing.T, resp error, jwt *sswGoJWT) {
				assert.NoError(t, resp)

				assert.True(t, jwt.initialized)

				assert.Nil(t, jwt.accessTokenSigningKey)
				assert.NotNil(t, jwt.accessTokenVerifyKey)
				assert.Nil(t, jwt.refreshTokenSigningKey)
				assert.NotNil(t, jwt.refreshTokenVerifyKey)

				assert.EqualValues(t, ModeValidationOnly, jwt.mode)
			},
		},
		{
			name: "success_hs256",
			JWTConfig: JWTConfig{
				SigningAlgorithm:   SigningAlgorithmHS256,
				AccessTokenSecret:  secret,
				RefreshTokenSecret: secret,
			},
			assert: func(t *testing.T, resp error, jwt *sswGoJWT) {
				assert.NoError(t, resp)

				assert.True(t, jwt.initialized)

				assert.NotNil(t, jwt.accessTokenSecret)
				assert.NotNil(t, jwt.refreshTokenSecret)
			},
		},
		{
			name: "error_invalid_config",
			JWTConfig: JWTConfig{
				SigningAlgorithm: SigningAlgorithmHS256,
			},
			assert: func(t *testing.T, resp error, jwt *sswGoJWT) {
				assert.Error(t, resp)

				assert.False(t, jwt.initialized)
			},
		},
		{
			name: "error_rs_256_invalid_access_token_private_key_path",
			JWTConfig: JWTConfig{
				SigningAlgorithm:           SigningAlgorithmRS256,
				AccessTokenPublicKeyFile:   accessTokenPublicKeyFile,
				AccessTokenPrivateKeyFile:  testString,
				RefreshTokenPublicKeyFile:  refreshTokenPublicKeyFile,
				RefreshTokenPrivateKeyFile: refreshTokenPrivateKeyFile,
			},
			assert: func(t *testing.T, resp error, jwt *sswGoJWT) {
				assert.ErrorIs(t, resp, InvalidKeyFilePath)

				assert.False(t, jwt.initialized)
			},
		},
		{
			name: "error_rs_256_invalid_access_token_validate_key_path",
			JWTConfig: JWTConfig{
				SigningAlgorithm:           SigningAlgorithmRS256,
				AccessTokenPublicKeyFile:   testString,
				AccessTokenPrivateKeyFile:  accessTokenPrivateKeyFile,
				RefreshTokenPublicKeyFile:  refreshTokenPublicKeyFile,
				RefreshTokenPrivateKeyFile: refreshTokenPrivateKeyFile,
			},
			assert: func(t *testing.T, resp error, jwt *sswGoJWT) {
				assert.ErrorIs(t, resp, InvalidKeyFilePath)

				assert.False(t, jwt.initialized)
			},
		},
		{
			name: "error_rs_256_invalid_refresh_token_private_key_path",
			JWTConfig: JWTConfig{
				SigningAlgorithm:           SigningAlgorithmRS256,
				AccessTokenPublicKeyFile:   accessTokenPublicKeyFile,
				AccessTokenPrivateKeyFile:  accessTokenPrivateKeyFile,
				RefreshTokenPublicKeyFile:  refreshTokenPublicKeyFile,
				RefreshTokenPrivateKeyFile: testString,
			},
			assert: func(t *testing.T, resp error, jwt *sswGoJWT) {
				assert.ErrorIs(t, resp, InvalidKeyFilePath)

				assert.False(t, jwt.initialized)
			},
		},
		{
			name: "error_rs_256_invalid_refresh_token_public_key_path",
			JWTConfig: JWTConfig{
				SigningAlgorithm:           SigningAlgorithmRS256,
				AccessTokenPublicKeyFile:   accessTokenPublicKeyFile,
				AccessTokenPrivateKeyFile:  accessTokenPrivateKeyFile,
				RefreshTokenPublicKeyFile:  testString,
				RefreshTokenPrivateKeyFile: refreshTokenPrivateKeyFile,
			},
			assert: func(t *testing.T, resp error, jwt *sswGoJWT) {
				assert.ErrorIs(t, resp, InvalidKeyFilePath)

				assert.False(t, jwt.initialized)
			},
		},
		{
			name: "error_rs_256_invalid_access_token_private_key_file",
			JWTConfig: JWTConfig{
				SigningAlgorithm:           SigningAlgorithmRS256,
				AccessTokenPublicKeyFile:   accessTokenPublicKeyFile,
				AccessTokenPrivateKeyFile:  goModFile,
				RefreshTokenPublicKeyFile:  refreshTokenPublicKeyFile,
				RefreshTokenPrivateKeyFile: refreshTokenPrivateKeyFile,
			},
			assert: func(t *testing.T, resp error, jwt *sswGoJWT) {
				assert.ErrorContains(t, resp, "init failed")

				assert.False(t, jwt.initialized)
			},
		},
		{
			name: "error_rs_256_invalid_access_token_validate_key_file",
			JWTConfig: JWTConfig{
				SigningAlgorithm:           SigningAlgorithmRS256,
				AccessTokenPublicKeyFile:   goModFile,
				AccessTokenPrivateKeyFile:  accessTokenPrivateKeyFile,
				RefreshTokenPublicKeyFile:  refreshTokenPublicKeyFile,
				RefreshTokenPrivateKeyFile: refreshTokenPrivateKeyFile,
			},
			assert: func(t *testing.T, resp error, jwt *sswGoJWT) {
				assert.ErrorContains(t, resp, "init failed")

				assert.False(t, jwt.initialized)
			},
		},
		{
			name: "error_rs_256_invalid_refresh_token_private_key_file",
			JWTConfig: JWTConfig{
				SigningAlgorithm:           SigningAlgorithmRS256,
				AccessTokenPublicKeyFile:   accessTokenPublicKeyFile,
				AccessTokenPrivateKeyFile:  accessTokenPrivateKeyFile,
				RefreshTokenPublicKeyFile:  refreshTokenPublicKeyFile,
				RefreshTokenPrivateKeyFile: goModFile,
			},
			assert: func(t *testing.T, resp error, jwt *sswGoJWT) {
				assert.ErrorContains(t, resp, "init failed")

				assert.False(t, jwt.initialized)
			},
		},
		{
			name: "error_rs_256_invalid_refresh_token_public_key_file",
			JWTConfig: JWTConfig{
				SigningAlgorithm:           SigningAlgorithmRS256,
				AccessTokenPublicKeyFile:   accessTokenPublicKeyFile,
				AccessTokenPrivateKeyFile:  accessTokenPrivateKeyFile,
				RefreshTokenPublicKeyFile:  goModFile,
				RefreshTokenPrivateKeyFile: refreshTokenPrivateKeyFile,
			},
			assert: func(t *testing.T, resp error, jwt *sswGoJWT) {
				assert.ErrorContains(t, resp, "init failed")

				assert.False(t, jwt.initialized)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &sswGoJWT{
				Config: tt.JWTConfig,
			}

			resp := g.Init()

			if tt.assert != nil {
				tt.assert(t, resp, g)
			}
		})
	}
}

func TestGoJWT_getSigningKeyOrSecret(t *testing.T) {
	tests := []struct {
		name string
		TokenType
		expected interface{}
		modify   func(t *testing.T, goJWT *sswGoJWT, expected interface{})
		assert   func(t *testing.T, resp interface{}, expected interface{})
	}{
		{
			name:      "success_hs256_refresh_token",
			TokenType: RefreshToken,
			modify: func(t *testing.T, goJWT *sswGoJWT, expected interface{}) {
				goJWT.signingMethod = jwt.SigningMethodHS256
				goJWT.refreshTokenSecret = []byte(expected.(string))
			},
			expected: secret + SigningAlgorithmHS256 + strconv.Itoa(RefreshToken),
			assert: func(t *testing.T, resp interface{}, expected interface{}) {
				assert.EqualValues(t, expected, resp)
			},
		},
		{
			name:      "success_hs256_access_token",
			TokenType: AccessToken,
			modify: func(t *testing.T, goJWT *sswGoJWT, expected interface{}) {
				goJWT.signingMethod = jwt.SigningMethodHS256
				goJWT.accessTokenSecret = []byte(expected.(string))
			},
			expected: secret + SigningAlgorithmHS256 + strconv.Itoa(AccessToken),
			assert: func(t *testing.T, resp interface{}, expected interface{}) {
				assert.EqualValues(t, expected, resp)
			},
		},
		{
			name:      "success_rs256_refresh_token",
			TokenType: RefreshToken,
			expected: &rsa.PrivateKey{
				PublicKey: rsa.PublicKey{
					N: big.NewInt(testInt),
					E: testInt,
				},
				D: big.NewInt(testInt),
				Primes: []*big.Int{
					big.NewInt(testInt),
					big.NewInt(testInt),
					big.NewInt(testInt),
				},
				Precomputed: rsa.PrecomputedValues{
					Dp:   big.NewInt(testInt),
					Dq:   big.NewInt(testInt),
					Qinv: big.NewInt(testInt),
					CRTValues: []rsa.CRTValue{
						{Exp: big.NewInt(testInt), Coeff: big.NewInt(testInt), R: big.NewInt(testInt)},
						{Exp: big.NewInt(testInt), Coeff: big.NewInt(testInt), R: big.NewInt(testInt)},
					},
				},
			},
			modify: func(t *testing.T, goJWT *sswGoJWT, expected interface{}) {
				goJWT.signingMethod = jwt.SigningMethodRS256

				privKey, ok := expected.(*rsa.PrivateKey)
				assert.True(t, ok)

				goJWT.refreshTokenSigningKey = privKey
			},
			assert: func(t *testing.T, resp interface{}, expected interface{}) {
				assert.Equal(t, expected, resp)
			},
		},
		{
			name:      "success_rs256_access_token",
			TokenType: AccessToken,
			expected: &rsa.PrivateKey{
				PublicKey: rsa.PublicKey{
					N: big.NewInt(testInt),
					E: testInt,
				},
				D: big.NewInt(testInt),
				Primes: []*big.Int{
					big.NewInt(testInt),
					big.NewInt(testInt),
					big.NewInt(testInt),
				},
				Precomputed: rsa.PrecomputedValues{
					Dp:   big.NewInt(testInt),
					Dq:   big.NewInt(testInt),
					Qinv: big.NewInt(testInt),
					CRTValues: []rsa.CRTValue{
						{Exp: big.NewInt(testInt), Coeff: big.NewInt(testInt), R: big.NewInt(testInt)},
						{Exp: big.NewInt(testInt), Coeff: big.NewInt(testInt), R: big.NewInt(testInt)},
					},
				},
			},
			modify: func(t *testing.T, goJWT *sswGoJWT, expected interface{}) {
				goJWT.signingMethod = jwt.SigningMethodRS256

				privKey, ok := expected.(*rsa.PrivateKey)
				assert.True(t, ok)

				goJWT.accessTokenSigningKey = privKey
			},
			assert: func(t *testing.T, resp interface{}, expected interface{}) {
				assert.Equal(t, expected, resp)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &sswGoJWT{}

			if tt.modify != nil {
				tt.modify(t, g, tt.expected)
			}

			resp := g.getSigningKeyOrSecret(tt.TokenType)

			tt.assert(t, resp, tt.expected)
		})
	}
}

func TestGoJWT_getKeyFunc(t *testing.T) {
	// Using secret "krabby patty's formula"
	const jwtHS256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.OqbUeMcUSlB9MK3moE4nCgC_zGxjP_k2mBNqGDFtcSQ"
	// Using ./Certificates/access_token_jwt_RS256.key and ./Certificates/access_token_jwt_RS256.key.pub
	const jwtRS256 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.G-GalDeOhhtsbBVxxURAgePvlX8YeIVkzQ7nSTs5fQC7I0sWqEEOOlaB-9ntTLbLAaSFGfjh7my3PhcEycaFDSPE7sikBE8UEcM7ftKDWAlDqxBQNZ0aSbKuFnh2GbO3v4MsgobEwx_dQ1dr-SeDxW9awEPR0RfLRLGynOTh0VOYA6f6dnWBZppE4SUenGwDIgHZKQgEoVaCdAo8IqWSJ2Zh7Reg2hKW2rT4ki91M7nLwlCT_Xf7yLiVbCJsOLNXsce6hk4yBirkD7MkxFCRsjNiis4N4aTy7BQ1Z5O5wxBt0eAkcspxgiql4uBb1rUvZdvgHRVZfFYLqfenogetxiaEMfqm-692c2PCKUYr10itHGJDUyjcuBOzmA1f8LxjuEZRwXJgehn6oow8C7e2rl66BH2bpIX9BYm7k85n61UKLp5c21lv-MRMgyxsBkeISBCoSatGXWktBhjspzMB82Qqepf2Wkz1R0-TRUkPcmH9MoGdP1WX0_a9jpk5Ja_idKgftTXM81WiPgHsUlzdPCse09whl-41hOpUcMOcYEGgu2W7yn0Ih7i-mliXOXcV9NGqVuKHjZRwHKA1DkAGuOrwkQsCW1gkKn-gfG4DhcoOivNPeTJsh7lVImakwLWJ7frikJgPbEsWPZIBER2b6fQgk7s22ARvHcVNf0JzbiA"

	// Unmarshalled value
	var publicKeyModulus big.Int
	publicKeyModulus.SetString("775022944367959914404878644861830075371315717976192822555668947583599028135341802475604042648740904113102863328517158687952274426150211668106179189511979855984876378321055821630297001325749245036289912107958940153069377468194744103504601932320545256459715588161660970567649651552877044037362412004154322533771653952212046361323367460781496181602061217473429286103209157240508012748157085209070303605553127018480721281454855721921722214168739106745792528135076119173289214747246633212451781484358230667954409728220358810295873322626391042138964776999523862047688471704988570394062354481372020258937355248604452513290325916340885174863929158922454672333407211491030644428915946870443123072766886435194740401704546967285019534904936421081918236597049627299829405067413566071646095700277786308230376887919195061958954699871900662599221565363144019569327332904589632046450066669943959398065933850869420755015998872600608412199464409174878530702899940178400959457118030274044291605668114926092558475141244759580381436181907163641477065016042238865131370467659646660493772072982124947517468539570851544584449542708553870453188316925666864431625985545292375440419673621382741314162484676596925158910572378097429554608175606357531751495674861", 10)

	tests := []struct {
		name string
		jwt.SigningMethod
		TokenType
		TokenString string
		expected    interface{}
		parseToken  func(tokenString string, signingMethod jwt.SigningMethod, expected interface{}) *jwt.Token
		modify      func(t *testing.T, goJWT *sswGoJWT, expected interface{})
		assert      func(t *testing.T, resp interface{}, expected interface{}, err error, keyFunc interface{})
	}{
		{
			name:          "success_rs256_access_token",
			SigningMethod: jwt.SigningMethodRS256,
			TokenType:     AccessToken,
			TokenString:   jwtRS256,
			expected: &rsa.PublicKey{
				N: &publicKeyModulus,
				E: 65537,
			},
			parseToken: func(tokenString string, signingMethod jwt.SigningMethod, expected interface{}) *jwt.Token {
				token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
					return expected, nil
				})

				return token
			},
			modify: func(t *testing.T, goJWT *sswGoJWT, expected interface{}) {
				goJWT.signingMethod = jwt.SigningMethodRS256

				goJWT.accessTokenVerifyKey = expected.(*rsa.PublicKey)
			},
			assert: func(t *testing.T, resp interface{}, expected interface{}, err error, keyFunc interface{}) {
				assert.Equal(t, resp, expected)
				assert.NoError(t, err)
				assert.NotNil(t, keyFunc)
			},
		},
		{
			name:          "success_rs256_refresh_token",
			SigningMethod: jwt.SigningMethodRS256,
			TokenType:     RefreshToken,
			TokenString:   jwtRS256,
			expected: &rsa.PublicKey{
				N: &publicKeyModulus,
				E: 65537,
			},
			parseToken: func(tokenString string, signingMethod jwt.SigningMethod, expected interface{}) *jwt.Token {
				token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
					return expected, nil
				})

				return token
			},
			modify: func(t *testing.T, goJWT *sswGoJWT, expected interface{}) {
				goJWT.signingMethod = jwt.SigningMethodRS256

				goJWT.refreshTokenVerifyKey = expected.(*rsa.PublicKey)
			},
			assert: func(t *testing.T, resp interface{}, expected interface{}, err error, keyFunc interface{}) {
				assert.Equal(t, resp, expected)
				assert.NoError(t, err)
				assert.NotNil(t, keyFunc)
			}},
		{
			name:          "success_hs256_refresh_token",
			SigningMethod: jwt.SigningMethodHS256,
			TokenType:     RefreshToken,
			TokenString:   jwtHS256,
			expected:      secret,
			parseToken: func(tokenString string, signingMethod jwt.SigningMethod, expected interface{}) *jwt.Token {
				token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
					return []byte(expected.(string)), nil
				})

				return token
			},
			modify: func(t *testing.T, goJWT *sswGoJWT, expected interface{}) {
				goJWT.signingMethod = jwt.SigningMethodHS256

				goJWT.refreshTokenSecret = []byte(expected.(string))
			},
			assert: func(t *testing.T, resp interface{}, expected interface{}, err error, keyFunc interface{}) {
				assert.EqualValues(t, resp, expected)
				assert.NoError(t, err)
				assert.NotNil(t, keyFunc)
			}},
		{
			name:          "success_hs256_access_token",
			SigningMethod: jwt.SigningMethodHS256,
			TokenType:     AccessToken,
			TokenString:   jwtHS256,
			expected:      secret,
			parseToken: func(tokenString string, signingMethod jwt.SigningMethod, expected interface{}) *jwt.Token {
				token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
					return []byte(expected.(string)), nil
				})

				return token
			},
			modify: func(t *testing.T, goJWT *sswGoJWT, expected interface{}) {
				goJWT.signingMethod = jwt.SigningMethodHS256

				goJWT.accessTokenSecret = []byte(expected.(string))
			},
			assert: func(t *testing.T, resp interface{}, expected interface{}, err error, keyFunc interface{}) {
				assert.EqualValues(t, resp, expected)
				assert.NoError(t, err)
				assert.NotNil(t, keyFunc)
			}},
		{
			name:          "success_unsupported_signing_method",
			TokenString:   jwtRS256,
			SigningMethod: jwt.SigningMethodNone,
			parseToken: func(tokenString string, signingMethod jwt.SigningMethod, expected interface{}) *jwt.Token {
				token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
					return expected, nil
				})

				return token
			},
			modify: func(t *testing.T, goJWT *sswGoJWT, expected interface{}) {
				goJWT.signingMethod = jwt.SigningMethodNone
			},
			assert: func(t *testing.T, resp interface{}, expected interface{}, err error, keyFunc interface{}) {
				assert.NoError(t, err)
				assert.Nil(t, keyFunc)
			},
		},
		{
			name:          "error_rs256_signing method",
			SigningMethod: jwt.SigningMethodRS256,
			TokenString:   jwtHS256,
			TokenType:     AccessToken,
			expected:      nil,
			parseToken: func(tokenString string, signingMethod jwt.SigningMethod, expected interface{}) *jwt.Token {
				token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
					return expected, nil
				})

				return token
			},
			modify: func(t *testing.T, goJWT *sswGoJWT, expected interface{}) {
				goJWT.signingMethod = jwt.SigningMethodRS256
			},
			assert: func(t *testing.T, resp interface{}, expected interface{}, err error, keyFunc interface{}) {
				assert.Equal(t, resp, expected)
				assert.ErrorContains(t, err, "unexpected signing method")
				assert.NotNil(t, keyFunc)
			},
		},
		{
			name:          "error_hs256_signing method",
			SigningMethod: jwt.SigningMethodHS256,
			TokenString:   jwtRS256,
			TokenType:     AccessToken,
			expected:      nil,
			parseToken: func(tokenString string, signingMethod jwt.SigningMethod, expected interface{}) *jwt.Token {
				token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
					return nil, nil
				})

				return token
			},
			modify: func(t *testing.T, goJWT *sswGoJWT, expected interface{}) {
				goJWT.signingMethod = jwt.SigningMethodHS256
			},
			assert: func(t *testing.T, resp interface{}, expected interface{}, err error, keyFunc interface{}) {
				assert.ErrorContains(t, err, "unexpected signing method")
				assert.NotNil(t, keyFunc)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &sswGoJWT{}

			if tt.modify != nil {
				tt.modify(t, g, tt.expected)
			}

			keyFunc := g.getKeyFunc(tt.TokenType)

			token := tt.parseToken(tt.TokenString, tt.SigningMethod, tt.expected)

			var resp interface{}
			var err error
			if keyFunc != nil {
				resp, err = keyFunc(token)
			}

			tt.assert(t, resp, tt.expected, err, keyFunc)
		})
	}
}

func TestGoJWT_generateToken(t *testing.T) {
	timeNow = func() time.Time {
		return testTime
	}
	t.Cleanup(func() {
		timeNow = time.Now
	})

	type Params struct {
		Claims             map[string]interface{}
		ExpiresAt          time.Time
		SigningKeyOrSecret interface{}
	}

	tests := []struct {
		name string
		JWTConfig
		Params
		signingKeyOrSecret func() interface{}
		modify             func(goJWT *sswGoJWT)
		assert             func(t *testing.T, resp interface{}, err error)
	}{
		{
			name: "success_rs256", // Access Token Keys
			JWTConfig: JWTConfig{
				Issuer: testString,
			},
			Params: Params{
				Claims:    testClaims,
				ExpiresAt: testTime,
			},
			signingKeyOrSecret: func() interface{} {
				modulus := &big.Int{}
				modulus.SetString("775022944367959914404878644861830075371315717976192822555668947583599028135341802475604042648740904113102863328517158687952274426150211668106179189511979855984876378321055821630297001325749245036289912107958940153069377468194744103504601932320545256459715588161660970567649651552877044037362412004154322533771653952212046361323367460781496181602061217473429286103209157240508012748157085209070303605553127018480721281454855721921722214168739106745792528135076119173289214747246633212451781484358230667954409728220358810295873322626391042138964776999523862047688471704988570394062354481372020258937355248604452513290325916340885174863929158922454672333407211491030644428915946870443123072766886435194740401704546967285019534904936421081918236597049627299829405067413566071646095700277786308230376887919195061958954699871900662599221565363144019569327332904589632046450066669943959398065933850869420755015998872600608412199464409174878530702899940178400959457118030274044291605668114926092558475141244759580381436181907163641477065016042238865131370467659646660493772072982124947517468539570851544584449542708553870453188316925666864431625985545292375440419673621382741314162484676596925158910572378097429554608175606357531751495674861", 10)

				privExponent := &big.Int{}
				privExponent.SetString("21544511255438835630660869602882505439379923079577856130521733946819661607304324892454714614628344352198827631831436342875033217246868089130487726323947927139810803290323179237786228953343823584366299518470734533706662814147826794521692081628687815530059740030301244765742960315354936825438069400026984501418175863384118586385364322733220762727141744785902252484332461809858026985647052042918116200803366117457855268340995742599158606393026044259574128927284122095618313335475006351743570866852617146119519387875492068488904972991412180604394016553961363647108459557723703310032235217856268350830940868574228477610042009537478761880127469767920876502433637152458565154588313300083444952847678876180852588257840819629742690291583380639814275181976397709613211065381453927319496590791547277703347286281932463695191903523152114538086189257753745262158069923171291172859626656097604512910548456887056428502919183172072182361261253546505073359199768183750279932224988969620109323907460011376876564241897323373213494835640721883378638460298885886092469012194756278853677895387277843613077782156670713024903760025119565780244199200423563091384300597781854553879106733489389887055370009800990939971879939610835912169669380380510849393772223", 10)

				primes := make([]*big.Int, 2)
				prime1 := &big.Int{}
				prime2 := &big.Int{}
				prime1.SetString("31601391161334329981235175299355019049336918371188843222338191020826590093646970855614231742311629504348352786414252281925053011210180321126722760009788252127105301592692293462336507100584918402599009587288431426123235810966146444603352270828209034599455152881927423413709478193205519409155945019246118536551261733710667873194976556124003567790344571043819547409137705733652136093528070000203714708290218968049132829221443714341641543154920825683062440110674471178700340690457264743207232722113895048114424307992652739237416385382264002787251671914744339487002307015062501667400659858218668134729203863553661417592251", 10)
				prime2.SetString("24524962854047831772101125127790094528063177173049290064139053092373214109523148394819477077349894870902619147430768017901067987346805850761406893313019772823620494354858571252751147779176675515851556428522140340116213340262840696188570211177811487359886701033101247755171466808307182475849693175675010481148199855053330174755622779659393405623119550593681410967856500055351646491925884396593706629566451541425830582608142520558931201218068302709261514677674223368164260063234722885912850230007270690117850353567146838274814731131736962703311350605599191518707509645419568996664206241029653724225554265523491201685111", 10)
				primes[0] = prime1
				primes[1] = prime2

				dp := &big.Int{}
				dp.SetString("10464040001710732790985009066196244386982322437297543170544289231166483537882919793974158765886517110546158716724532535362552075869693808822054879151813706141726233270717540632408632384604014743653220425923466902334564297019643010731912471264216614429143480365148038749117435742721714095825154689147504743300714571665703396801870489104582166175111273574041045490725809117383844322530061599927076504640219140724083060361849795457954485679920302091156720827040400064833240662886813589153305114707625256559365273170095626809148618020057541915042625268502783331666647306618724517208015618401869435460250744510398804082723", 10)

				dq := &big.Int{}
				dq.SetString("23766802200641345250437379770069986321800211261387208161245333185066682962447543795159677871424831364662652313540069084409031981085234087427067354337293418859590173748743804550612297581569034876287413222025262907077236148335036322316131081406136768141870458966893409008326518279176609643769013889563080254943059966038910122967245347802733335131756805739586799700620018844552518735198511434946105280229410925850983812686356403607401613143121228822923051996486985982505765001084890751899095639989498585532978223070983762541339371483402448056060045292158784389652145278090883722891502549308548418134628941783457431835803", 10)

				qinv := &big.Int{}
				qinv.SetString("1502949234508924879857288338573911775227899437615874596418784932672315502648861724554229491856942481528382220643854876885371966489281641547657761847926093298089069459512523598896574192401038026865029272200157532262272478668155752778021130495882655365425738280105904514157010683772607216382381158180766384385966760431763738470397452165949080911355206809704047615211521575067649428011184518652523681697371267307914976300656063018878794371466780009848848010844381049796130584206887913219680249415144453642247772115060842979938234575367027622104982178695993844789151478041084892054220308665341004815564601171213629359958", 10)

				return &rsa.PrivateKey{
					PublicKey: rsa.PublicKey{
						N: modulus,
						E: 65537,
					},
					D:      privExponent,
					Primes: primes,
					Precomputed: rsa.PrecomputedValues{
						Dp:        dp,
						Dq:        dq,
						Qinv:      qinv,
						CRTValues: []rsa.CRTValue{},
					},
				}
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.signingMethod = jwt.SigningMethodRS256
			},
			assert: func(t *testing.T, resp interface{}, err error) {
				assert.NoError(t, err)

				const generatedJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwiZXhwIjoxNjgwMjgyNTAxLCJpYXQiOjE2ODAyODI1MDEsImlzcyI6InRoaXMgaXMgYSB0ZXN0IHN0cmluZyIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.ppTuw9P5z3vnZIUDdwj0HaX0YXCCB4Tyz2widqtZY4wZZf8UnNMdJ3cQy-LqpMay8gqCLFm6ujnBWxIlPk6GLgNfD96CVyqo--y94X14GUdi4t9zkTegdjCGa2Vtyo0FCW8B8vUz4lo9JqVNU8FXTaNxMmcVjzyZ_eTOzbfH_0dp1cbFhyRs-axEH6hV-5VVFzaJhxKKR9CdFrRClbnscIXeJfJkCFmrtE9V231Nxv_T2MkgiYDbXGm0SACQ1doarx2PSqI0ahQoOHnEodDqQjOVrEVsmNahE4Go93Tenu4HXwPk0K2-67-E3hdmw51v_dpLvYjvpoihmLTKbGKMesSKAl00IrPJCBmMl4WXrARybhoUESaUjNH1RBraRczUc1p6TYOnCewjgxposZ4tTE09x1GuDUSBxSKt5osY32dn8deJoeSPbcMYl2TrMHHd6HJU5dnAMjubFt412FxsLyR9-Xjw8gcRZ_VVKd4LLX0ptEIgXdymqbETy-2Jbo6fBy-U8tX5v5awqStMcJ1bLrUGHW8v8k6imJVKUnyWeYKItKVQf-SCSoj3ZYdy46GG_thu84tJmbGfVo-v950cb6ymzoBj-XaYbpcWkcZGHCs99AEjJfPZbSgE7tKLViECpWBr-x4bg3uyVLflH9hubraasYrr9CY1-rMx7nuFSJY"

				assert.EqualValues(t, generatedJWT, resp)
			},
		},
		{
			name: "success_hs256", // Access Token Keys
			JWTConfig: JWTConfig{
				Issuer: testString,
			},
			Params: Params{
				Claims:    testClaims,
				ExpiresAt: testTime,
			},
			signingKeyOrSecret: func() interface{} {
				return []byte(secret)
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.signingMethod = jwt.SigningMethodHS256
			},
			assert: func(t *testing.T, resp interface{}, err error) {
				assert.NoError(t, err)

				const generatedJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwiZXhwIjoxNjgwMjgyNTAxLCJpYXQiOjE2ODAyODI1MDEsImlzcyI6InRoaXMgaXMgYSB0ZXN0IHN0cmluZyIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.NygeKuAjNGkLvZ6455WLGod9YD6IC7dC9FrSeZKMzXY"

				assert.EqualValues(t, generatedJWT, resp)
			},
		},
		{
			name: "error_invalid_secret",
			JWTConfig: JWTConfig{
				Issuer: testString,
			},
			Params: Params{
				Claims:    testClaims,
				ExpiresAt: testTime,
			},
			signingKeyOrSecret: func() interface{} {
				return secret
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.signingMethod = jwt.SigningMethodHS256
			},
			assert: func(t *testing.T, resp interface{}, err error) {
				assert.ErrorContains(t, err, "generate token failed")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &sswGoJWT{
				Config: tt.JWTConfig,
			}

			if tt.modify != nil {
				tt.modify(g)
			}

			resp, err := g.generateToken(tt.Params.Claims, tt.Params.ExpiresAt, tt.signingKeyOrSecret())

			tt.assert(t, resp, err)
		})
	}
}

func TestGoJWT_GenerateTokens(t *testing.T) {
	timeNow = func() time.Time {
		return testTime
	}
	t.Cleanup(func() {
		timeNow = time.Now
	})

	type Params struct {
		Claims map[string]interface{}
	}
	tests := []struct {
		name string
		JWTConfig
		Params
		modify func(goJWT *sswGoJWT)
		assert func(t *testing.T, resp Tokens, err error)
	}{
		{
			name: "success_hs256",
			JWTConfig: JWTConfig{
				Issuer:             testString,
				AccessTokenMaxAge:  900,
				RefreshTokenMaxAge: 7776000,
			},
			Params: Params{
				Claims: testClaims,
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodHS256
				goJWT.refreshTokenSecret = []byte(secret)
				goJWT.accessTokenSecret = []byte(secret)
			},
			assert: func(t *testing.T, resp Tokens, err error) {
				const expectedAccessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwiZXhwIjoxNjgwMjgzNDAxLCJpYXQiOjE2ODAyODI1MDEsImlzcyI6InRoaXMgaXMgYSB0ZXN0IHN0cmluZyIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.IUjsoGBIhsnKEEnvH3I9f2Y0y6MJ8Xi7JpLf2X00lVY"
				const expectedRefreshToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODgwNTg1MDEsImlhdCI6MTY4MDI4MjUwMSwiaXNzIjoidGhpcyBpcyBhIHRlc3Qgc3RyaW5nIn0.QrW_xzfaLINSx5--D0gHZw3pnm1LinFeDZpMLg-B-9U"
				assert.EqualValues(t, expectedAccessToken, resp.AccessToken)
				assert.EqualValues(t, expectedRefreshToken, resp.RefreshToken)
			},
		},
		{
			name: "success_rs256",
			JWTConfig: JWTConfig{
				Issuer:             testString,
				AccessTokenMaxAge:  900,
				RefreshTokenMaxAge: 7776000,
			},
			Params: Params{
				Claims: testClaims,
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodRS256

				// Access Token Signing Key
				{
					modulus := &big.Int{}
					modulus.SetString("775022944367959914404878644861830075371315717976192822555668947583599028135341802475604042648740904113102863328517158687952274426150211668106179189511979855984876378321055821630297001325749245036289912107958940153069377468194744103504601932320545256459715588161660970567649651552877044037362412004154322533771653952212046361323367460781496181602061217473429286103209157240508012748157085209070303605553127018480721281454855721921722214168739106745792528135076119173289214747246633212451781484358230667954409728220358810295873322626391042138964776999523862047688471704988570394062354481372020258937355248604452513290325916340885174863929158922454672333407211491030644428915946870443123072766886435194740401704546967285019534904936421081918236597049627299829405067413566071646095700277786308230376887919195061958954699871900662599221565363144019569327332904589632046450066669943959398065933850869420755015998872600608412199464409174878530702899940178400959457118030274044291605668114926092558475141244759580381436181907163641477065016042238865131370467659646660493772072982124947517468539570851544584449542708553870453188316925666864431625985545292375440419673621382741314162484676596925158910572378097429554608175606357531751495674861", 10)

					privExponent := &big.Int{}
					privExponent.SetString("21544511255438835630660869602882505439379923079577856130521733946819661607304324892454714614628344352198827631831436342875033217246868089130487726323947927139810803290323179237786228953343823584366299518470734533706662814147826794521692081628687815530059740030301244765742960315354936825438069400026984501418175863384118586385364322733220762727141744785902252484332461809858026985647052042918116200803366117457855268340995742599158606393026044259574128927284122095618313335475006351743570866852617146119519387875492068488904972991412180604394016553961363647108459557723703310032235217856268350830940868574228477610042009537478761880127469767920876502433637152458565154588313300083444952847678876180852588257840819629742690291583380639814275181976397709613211065381453927319496590791547277703347286281932463695191903523152114538086189257753745262158069923171291172859626656097604512910548456887056428502919183172072182361261253546505073359199768183750279932224988969620109323907460011376876564241897323373213494835640721883378638460298885886092469012194756278853677895387277843613077782156670713024903760025119565780244199200423563091384300597781854553879106733489389887055370009800990939971879939610835912169669380380510849393772223", 10)

					primes := make([]*big.Int, 2)
					prime1 := &big.Int{}
					prime2 := &big.Int{}
					prime1.SetString("31601391161334329981235175299355019049336918371188843222338191020826590093646970855614231742311629504348352786414252281925053011210180321126722760009788252127105301592692293462336507100584918402599009587288431426123235810966146444603352270828209034599455152881927423413709478193205519409155945019246118536551261733710667873194976556124003567790344571043819547409137705733652136093528070000203714708290218968049132829221443714341641543154920825683062440110674471178700340690457264743207232722113895048114424307992652739237416385382264002787251671914744339487002307015062501667400659858218668134729203863553661417592251", 10)
					prime2.SetString("24524962854047831772101125127790094528063177173049290064139053092373214109523148394819477077349894870902619147430768017901067987346805850761406893313019772823620494354858571252751147779176675515851556428522140340116213340262840696188570211177811487359886701033101247755171466808307182475849693175675010481148199855053330174755622779659393405623119550593681410967856500055351646491925884396593706629566451541425830582608142520558931201218068302709261514677674223368164260063234722885912850230007270690117850353567146838274814731131736962703311350605599191518707509645419568996664206241029653724225554265523491201685111", 10)
					primes[0] = prime1
					primes[1] = prime2

					dp := &big.Int{}
					dp.SetString("10464040001710732790985009066196244386982322437297543170544289231166483537882919793974158765886517110546158716724532535362552075869693808822054879151813706141726233270717540632408632384604014743653220425923466902334564297019643010731912471264216614429143480365148038749117435742721714095825154689147504743300714571665703396801870489104582166175111273574041045490725809117383844322530061599927076504640219140724083060361849795457954485679920302091156720827040400064833240662886813589153305114707625256559365273170095626809148618020057541915042625268502783331666647306618724517208015618401869435460250744510398804082723", 10)

					dq := &big.Int{}
					dq.SetString("23766802200641345250437379770069986321800211261387208161245333185066682962447543795159677871424831364662652313540069084409031981085234087427067354337293418859590173748743804550612297581569034876287413222025262907077236148335036322316131081406136768141870458966893409008326518279176609643769013889563080254943059966038910122967245347802733335131756805739586799700620018844552518735198511434946105280229410925850983812686356403607401613143121228822923051996486985982505765001084890751899095639989498585532978223070983762541339371483402448056060045292158784389652145278090883722891502549308548418134628941783457431835803", 10)

					qinv := &big.Int{}
					qinv.SetString("1502949234508924879857288338573911775227899437615874596418784932672315502648861724554229491856942481528382220643854876885371966489281641547657761847926093298089069459512523598896574192401038026865029272200157532262272478668155752778021130495882655365425738280105904514157010683772607216382381158180766384385966760431763738470397452165949080911355206809704047615211521575067649428011184518652523681697371267307914976300656063018878794371466780009848848010844381049796130584206887913219680249415144453642247772115060842979938234575367027622104982178695993844789151478041084892054220308665341004815564601171213629359958", 10)

					goJWT.accessTokenSigningKey = &rsa.PrivateKey{
						PublicKey: rsa.PublicKey{
							N: modulus,
							E: 65537,
						},
						D:      privExponent,
						Primes: primes,
						Precomputed: rsa.PrecomputedValues{
							Dp:        dp,
							Dq:        dq,
							Qinv:      qinv,
							CRTValues: []rsa.CRTValue{},
						},
					}
				}

				// Refresh Token Signing Key
				{
					modulus := &big.Int{}
					modulus.SetString("819916210207963106248339561457160367534375955348566045978913574284599733129731887901816257373184343206273796910965368783816593980682979140467046323153757954553519717606060893170003911869615971925260797519018677238579292216323353755099193565639646071101889935448068769600679399081524685480464165241935636634596496416300745040937931378625560590461178905128563409635478272926777752864485934711535817828796582113128460615145009604780488008344227887417991179087413978225159328376657264248723197815821422279478048254809301546507874694609616361606655765131912309488177745199940604353789879872118160626875501716417233318131043542347892847387739074999149344361829304392676161884107662745326971479711203723138030889207123014199197126950624136720867681201324065861073058302878750449802189101144369201867295949454804971138832933635021773794498232108653321037553635869102070574969559397223092608724569780438024626673591493643467524275050173642594459895911635610086010432221617051426630889692282521721375272850323180037914720148638097877032782762163526334529363694728173863955049581861387357196690701611596485124473846446926659774125458593556272264913369200314469611095817896582492844921067314858553124261312747963982400866679110077700559238035117", 10)

					privExponent := &big.Int{}
					privExponent.SetString("51137639947282438878650044363583059985912716747596986632571055051166538126062820876736407708819308220633293328555944655749428992722304610169202921187893642358324486102732409186145093455102541850321246164136119187828140698143364946121548952493279419497825275968445017253502251304541436927253265719004713592991946215139986501591983070786456183736058543642720950560523329425945711046181336621044641277068007833550705445235595568297911786229260287926225474838942957962606447575256520249884127608407007698969536631849688268784822891102992307827138951126488724919250599409566462003084000396375833217302494976362290632587094407894282982846961956847148526224335727334713671448020760732397179938661117882992947469103841443424535386584212348391492819877835387292840024991073748478491105267430383705907868829870356985107715143284138572403799156053533714889899383430136988862912102407304937518694861563866630677918658617975115261410047975647324133120127125578418344703260874559742930566106621632598729561810145150215468794392876218175657417922627674202435386314429767092316965466493475246068712399701604891099469050355109157889525237921081442189673886168564457381718872900882469206512953721529254380553651614063286009750518919954783707978961473", 10)

					primes := make([]*big.Int, 2)
					prime1 := &big.Int{}
					prime2 := &big.Int{}
					prime1.SetString("29794695116749230965976364224673406030823069308363828136840701379212722638702488898212489736733300052360637637571182948072671923494723905666290722496531335194697247179522081947450739553183672198735264823214821930999107371292977983741267380719093641988068945223949756319624259502867086215531749485519411784930052073859680955974190377762130397320766767156117676237648192257272248543236259133663840651762516017557727711614825046043892822130415978425738501447730186198915594855559117723993815855382291641644998517129720482182124932735319785083058675420698938045976820672339534472229021050475806880106276347923044372691341", 10)
					prime2.SetString("27518865589835932590648263897646328449108275017978927178994247222625634128481002384454905242021107978328689785340494682087991214539365928285858017079404671825457380182570194150059398717869437654635321310255974584530246381289621894341813904679530056242541102141359326360874007509500112016437763427641351137138059183736194892531591034696220874629795600020374862156857709128215735658406135663595618793284460005515373485961573654232770471672095272886628321371972228709040051283479630890167332579852898871118865548251756239084154890402674370181622021128916992565745406024074302120663951778197671412931620989310268426885537", 10)
					primes[0] = prime1
					primes[1] = prime2

					dp := &big.Int{}
					dp.SetString("19610207575277752685008323097353973620085647719857084191870602163546405710063503953864164438317147531296460083565512252088357773775804746493056598789811543763420140639466026897833096580963084979361973360840004028161900856931544094613417893210218719916312219848865110378061132393246132168194485772279473081510563440589855166332708270820597444015308520397319620435951520103413925582686055781170785457280255861839153223988059849567470541565764274064943928772263630951832158690427430963035739306375255961706471322098821932632344461503242732037745639322395725965686713760186853524872954560206813399657967716979118955949173", 10)

					dq := &big.Int{}
					dq.SetString("16301706193359482597109076541470061329931650228466299798130730120756137659185161902004864217327394831051996941212964051493081510018185199716829665640382189820707872969893688259880007269540033539312252303707336333601137605639669054183625146426803109289472713252574776497371127661341270561883566375502695808430518206359618144143826521507108702194982293659932759716125041449634855203416412177361989538912104472193163325228285914495305674988567599665495389178999310849917785540664505699817909772306164347978206466267573011733282654227429193792225944524283143909241098891811291808147101635487864828482297353677961321650017", 10)

					qinv := &big.Int{}
					qinv.SetString("28138733744198538610167996567240892089898548500578617544368065810057920210024256159552043682996804019014760158040467784075155415105057682663169889780401844415465504426886182988462561011182361547855635443122638867588410602493856063465579581365916309183657112935136115963766735374866778033502270819024151574624059944640452436320400679093724386400626511733999488688498872874214069439665089040569038956730937420152950652717477944327898891604684007417657008662158577468973910384543491291258750009142255271120933927285343178640281091137587043828924980051200608894144285591778725275810560309411809996883150826117703056993162", 10)

					goJWT.refreshTokenSigningKey = &rsa.PrivateKey{
						PublicKey: rsa.PublicKey{
							N: modulus,
							E: 65537,
						},
						D:      privExponent,
						Primes: primes,
						Precomputed: rsa.PrecomputedValues{
							Dp:        dp,
							Dq:        dq,
							Qinv:      qinv,
							CRTValues: []rsa.CRTValue{},
						},
					}
				}

			},
			assert: func(t *testing.T, resp Tokens, err error) {
				const expectedAccessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwiZXhwIjoxNjgwMjgzNDAxLCJpYXQiOjE2ODAyODI1MDEsImlzcyI6InRoaXMgaXMgYSB0ZXN0IHN0cmluZyIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.bzTXUKBOYijTBGDTHo09ujQzuec6XJox62SlfW797xqUtMzspM5gQvf1GZcgYhHSQKjyrgGvKm1uq6HEQDgojZigvqvZ7iE2KskxYO7y-BLqSFmwUr-1jcPPL2ItvP2zF6xXxmK0rCPE4dvQaGh9LLgWhYqyW_Yplj21NEwnAFFkwVCkHwCbZ5dMaHsI81GfzNMWSeJ4o_6peS2x1sc_1_Zj1XakxRAJr4XxSWl96hVq8gIdeMQuUXhCklMpVip1gr2i-R3bkU3bDC0fLLgcJCwAQhj3AVYMxQvXRk58d3Hs7vARm2nLGtBr3liW1u8BZrqrlFa5UQYcVwLdi9PGUI1x5ZHVqLMvR6R6QNWWg3KmcdMSabizW59XN2OY0WivDunZvfi-lk6SJgKSZbF2C9_z2grhAm2C5vaSp5ZJ6jPZnHF7ngbWB3wmQmxwypBMHr2NCz67wZB7ik1e0j-zM-QmuUM9Ugn8Sq7L-s2jDzWG03Og2DYbPUChZMnziGHOdEZeejr0AR2Bn4OiVjaQtgtEle4ntM_Y4-wn85yr2213FCGfzbHgsq9oMYGpvPjo1Sepzjewkcsxk7fu16EnVKVioIC_5momTYyBxlBDvC-jFt2RYbI3GI8Th_EdrV_RMbzvdV-aYtHrF9Ml8VogAmuPq1G90NXX0vTNrxazSB4"
				const expectedRefreshToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODgwNTg1MDEsImlhdCI6MTY4MDI4MjUwMSwiaXNzIjoidGhpcyBpcyBhIHRlc3Qgc3RyaW5nIn0.Ix2Db7hQefFqx0CRmAqEUyfKqvyVsraWtjGWZcKkR-f-uKIdL5CcEr5C_p1gMBiKshkIVdGkkhgE3AqsnK3sUmyNwSD4E_mafXduhb4aqSCOzeEkYxyGIU0JkNa3dSwKOAg1uRlPlxUlWxiUaQdn0RwsvSbJBgm0PVQnoN6KsGvPmXonP9JCrK1vO8dO-yuOMDjnIQ9i0NkiXkkJWV3cjGvtI0Th0a5OCXTfNjkcvNPsQdc5jbt2aye3LzTsl1hUTGIPyT_q4aHIo87xtSseV3qc1hWLthZuXF5aIH4g5NN_wF5kj1W13iOFPSRnNQWS3uD_hJwWDO5l_V__wW_86zlyqDLrj6JDDFoHXcOTW0ih5NpfTmxzjJseah9o_RmH39JRApPn3HQ_QH41PGGUCCn3PFmg65AR4LLok8AmB6_2Pm5JLEFNlRowuFNRlg8kJlB2sAXB8-6_bcglQ7QcHP9Klb3ULk6VNTC-vDEsM8uyoInD8MwXrbhlSET2ElNblp4k7pCkjg-rihZptwGqnaztkcud0queo7Qiy_XoicJ_DuuO-8PQ8MMFWeA3unT-CgR6L5lcOaN0Ce6ktnCl1WPeAcaR9xM5vf3mDRXTUoetcx2N5uPYZfgPcOlT_T2p4rLxE4Y5EQLcFZfvC4Y1z2oDCmNb_nWlnHb-i-QF3ck"
				assert.EqualValues(t, expectedAccessToken, resp.AccessToken)
				assert.EqualValues(t, expectedRefreshToken, resp.RefreshToken)
			},
		},
		{
			name:      "error_not_initialized",
			JWTConfig: JWTConfig{},
			Params:    Params{},
			modify:    func(goJWT *sswGoJWT) {},
			assert: func(t *testing.T, resp Tokens, err error) {
				assert.ErrorIs(t, err, ErrorNotInitialized)
			},
		},
		{
			name:      "error_mode_validation_only",
			JWTConfig: JWTConfig{},
			Params:    Params{},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.mode = ModeValidationOnly
			},
			assert: func(t *testing.T, resp Tokens, err error) {
				assert.ErrorIs(t, err, ErrorValidationOnly)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &sswGoJWT{
				Config: tt.JWTConfig,
			}

			if tt.modify != nil {
				tt.modify(g)
			}

			resp, err := g.GenerateTokens(tt.Params.Claims)

			tt.assert(t, resp, err)
		})
	}
}

func TestGoJWT_ValidateToken(t *testing.T) {
	type Params struct {
		signedToken string
		TokenType
	}
	tests := []struct {
		name   string
		Params Params
		modify func(goJWT *sswGoJWT)
		assert func(t *testing.T, err error)
	}{
		{
			name: "success_rs256_access_token",
			Params: Params{
				signedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjo5MjIzMzcxOTc0NzE5MTc5MDAwfQ.Dc1FOioAMAR_HAvvXHB1OST1K37SbIpsRAr6lSlSm0NL4wlcsTsNw9ogO3Yma2_mzo5WC7Ktb-tCm8q7_FpQd6K3f13ZrGH1KYen9JCZEYDKaqQtAalOtU8k2qk4hWfxTFh8uHuNxvLYzOXcZfYXyqYOdtkKECyj3UDLDFIV8SODcorGKiOnGhOK71b2GuBHp3JiTJhK-fDr1_EMrEdteea6tDlLBVSvhOItSZHY1G9nwWpnLgPUg4lHxQ3AkQ6hH1g8SDuridoPnFuNjpbmdPFW-A9cxM0IGvl1n4Sulj-xjFkC9BLTa3uIWTCokYZTeSQflk0AXy3Tl2JEgsMnIyXi-xOZRYaziPd2nUwHDmPgN7k5SwKh8ug9LG-32ye0V98dX3grOsKH-0stqt0YRvonXeGRkgA23V5WL77vC9P1xpzCFndhpvoWCTQuUQ6qUr0ixJRABWTYzrFdcTcxKmBYGP_gAx4XIGW6NzI9fCIilcshtCMRnKaQWuyeiIqvyEY_zoV8F5LJN_LrXioDoD2T8cvKS87zVr1z8xtmU3-8NRgLg5Rh--kmV4m02bTu2YC3IfXLQDaaoV0Rho2EYQSbC4o5iUIJ-qL4Rc8wZ189M-UyNsewbDUL2ngJ0oZyllqkbX32zJ6yEibSHO8B8C85NgVB6LwY_x7tkwwNp7I",
				TokenType:   AccessToken,
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodRS256

				modulus := &big.Int{}
				modulus.SetString("775022944367959914404878644861830075371315717976192822555668947583599028135341802475604042648740904113102863328517158687952274426150211668106179189511979855984876378321055821630297001325749245036289912107958940153069377468194744103504601932320545256459715588161660970567649651552877044037362412004154322533771653952212046361323367460781496181602061217473429286103209157240508012748157085209070303605553127018480721281454855721921722214168739106745792528135076119173289214747246633212451781484358230667954409728220358810295873322626391042138964776999523862047688471704988570394062354481372020258937355248604452513290325916340885174863929158922454672333407211491030644428915946870443123072766886435194740401704546967285019534904936421081918236597049627299829405067413566071646095700277786308230376887919195061958954699871900662599221565363144019569327332904589632046450066669943959398065933850869420755015998872600608412199464409174878530702899940178400959457118030274044291605668114926092558475141244759580381436181907163641477065016042238865131370467659646660493772072982124947517468539570851544584449542708553870453188316925666864431625985545292375440419673621382741314162484676596925158910572378097429554608175606357531751495674861", 10)

				goJWT.accessTokenVerifyKey = &rsa.PublicKey{
					N: modulus,
					E: 65537,
				}
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "success_rs256_refresh_token",
			Params: Params{
				signedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjo5MjIzMzcxOTc0NzE5MTc5MDAwfQ.b67cB20noDG78DswXJmmyc85bU0_0Rf1bJXUeIzaXJVJ0OOhfy-CsxxS5gNPH-sTkjEch89ynVoPqUGGgOly0ca3rfW6aco20avdnpaWrW4Q2OtGurjR-j8GbNU6GBNlU-a8I3GgoyumuwdEPjaANU1Vpe0e17cCkiEA3AzoDTj1Dp69j_74yLmuLjDZrM_jNzqeHO9X_6ijyX0qKKMpOANvKKmKsUBe4UYicxPnwEP_A560pNf8OiCBtOh9Kne4GeyeYPxJay5fPsL5507p1Kmzqy1_PdAy8pMO4C_rwsnHKYb_nc_Ev08fpCgxGIqMe-pSrb-btgZ2sp9rMlC6wVt12pYE08xvBaFJ9ZBLpvp3r5wnDZVqH5ARzUk4E76KbVpcKehBu3jNC-PXeg3ji42mbU-2LkUVxht-2kEhoZxCVVk9ObE1awugQqWNfvVg8fr7RP3sewQB3kpkADmxvaBIeB-P-Xr2hQf3Lagi_6Cn8684tvNcAxdf7Y4wikf3UlJjKMwPK2jXDgwgMZepz7cG_u4I_0Qk_s2tVynLwpIpCe9pCuKLc6ZM5sR8WYSZyHl7xVMhtP_Ty90viNGZ9Pgpcp9eC9y8eM3kvR7Ku3xQzVsqZgaqakkFlAVKS_jrvoFkaP-tiQ74jReYKmIidam9OfcBB9vpcIuZ3_Ni5XQ",
				TokenType:   RefreshToken,
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodRS256

				modulus := &big.Int{}
				modulus.SetString("819916210207963106248339561457160367534375955348566045978913574284599733129731887901816257373184343206273796910965368783816593980682979140467046323153757954553519717606060893170003911869615971925260797519018677238579292216323353755099193565639646071101889935448068769600679399081524685480464165241935636634596496416300745040937931378625560590461178905128563409635478272926777752864485934711535817828796582113128460615145009604780488008344227887417991179087413978225159328376657264248723197815821422279478048254809301546507874694609616361606655765131912309488177745199940604353789879872118160626875501716417233318131043542347892847387739074999149344361829304392676161884107662745326971479711203723138030889207123014199197126950624136720867681201324065861073058302878750449802189101144369201867295949454804971138832933635021773794498232108653321037553635869102070574969559397223092608724569780438024626673591493643467524275050173642594459895911635610086010432221617051426630889692282521721375272850323180037914720148638097877032782762163526334529363694728173863955049581861387357196690701611596485124473846446926659774125458593556272264913369200314469611095817896582492844921067314858553124261312747963982400866679110077700559238035117", 10)

				goJWT.refreshTokenVerifyKey = &rsa.PublicKey{
					N: modulus,
					E: 65537,
				}
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "success_hs256_access_token",
			Params: Params{
				signedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjo5MjIzMzcxOTc0NzE5MTc5MDAwfQ.0ogFvnrEw2MuVTJTRIvbNcVgr4k51Hdbk20q3ki0m2E",
				TokenType:   AccessToken,
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodHS256

				goJWT.accessTokenSecret = []byte(secret)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "success_hs256_refresh_token",
			Params: Params{
				signedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjo5MjIzMzcxOTc0NzE5MTc5MDAwfQ.0ogFvnrEw2MuVTJTRIvbNcVgr4k51Hdbk20q3ki0m2E",
				TokenType:   RefreshToken,
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodHS256

				goJWT.refreshTokenSecret = []byte(secret)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:   "error_not_initialized",
			Params: Params{},
			modify: func(goJWT *sswGoJWT) {},
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, ErrorNotInitialized)
			},
		},
		{
			name: "error_expired_token",
			Params: Params{
				signedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxfQ.M_ybVRzvzc6o5aHGOL1ipU0TQtD75R34unxe2emL4RRxbqjqkK_dZeZzSpxbcGrGlvvoGrRsPqNGr2wAwFIUXUrDD3s3oRyWqBZYJLeyf6hKm0EHKkcP7UoUbfOeVdoye5dKOgB9WdDRPh_dxcKPC9tbn4akCj1o6zefiwg5C3l1o8lcE000ctfiVKFbQZfXEeOEPcIBXoEa9yMMLc9sGxpl9drRobdwLszts03dIw1ymqwOLm7hacDhI3Pe2bFlaxXb634sCx-VzuYdsjeEFebJXNXosMjGKRPmnS8I00YZkDhXDw68KHL2boDlyerNFbqxBfAkRRVjpV6yyDe9Rk1ZDKtVvWCuC5JblUYmyotn_kgtOwYFa1Gz1FdNVBNat_aNGQB_IP9-Z8En_f9FOLmqcECA9cykZH4jF2ezZIylh4SX8C0rAsHWJWd2BWp475V9t1SxRGB0vorlkWL-GlfMITpDBVqQSfQwoQrifehuNRRYr9m6kFdDnlBC_59MAFCghLX5pPAI4ni3dtxAG7Hr_P4Ja4U7izuVlF_C0kD0YuuTFoRS2NZJCP6UHHWf1NsYFIVs_Opc8rxk0LjJrsNYecHRdRwb5IxQ_ZZYNbsiXXi4OoliM_3OIuABZLIjDUqk1TqQOBh0loQQah83K0XxyStr44Q2xaqk_USVSnE",
				TokenType:   AccessToken,
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodRS256

				modulus := &big.Int{}
				modulus.SetString("775022944367959914404878644861830075371315717976192822555668947583599028135341802475604042648740904113102863328517158687952274426150211668106179189511979855984876378321055821630297001325749245036289912107958940153069377468194744103504601932320545256459715588161660970567649651552877044037362412004154322533771653952212046361323367460781496181602061217473429286103209157240508012748157085209070303605553127018480721281454855721921722214168739106745792528135076119173289214747246633212451781484358230667954409728220358810295873322626391042138964776999523862047688471704988570394062354481372020258937355248604452513290325916340885174863929158922454672333407211491030644428915946870443123072766886435194740401704546967285019534904936421081918236597049627299829405067413566071646095700277786308230376887919195061958954699871900662599221565363144019569327332904589632046450066669943959398065933850869420755015998872600608412199464409174878530702899940178400959457118030274044291605668114926092558475141244759580381436181907163641477065016042238865131370467659646660493772072982124947517468539570851544584449542708553870453188316925666864431625985545292375440419673621382741314162484676596925158910572378097429554608175606357531751495674861", 10)

				goJWT.accessTokenVerifyKey = &rsa.PublicKey{
					N: modulus,
					E: 65537,
				}
			},
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, jwt.ErrTokenExpired)
			},
		},
		{
			name: "error_invalid_signature",
			Params: Params{
				signedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxfQ.VvC_YHa4Zo7VqyeliJI2UNPyAo4gobgcTUQEuLBhmLA",
				TokenType:   AccessToken,
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodRS256

				modulus := &big.Int{}
				modulus.SetString("775022944367959914404878644861830075371315717976192822555668947583599028135341802475604042648740904113102863328517158687952274426150211668106179189511979855984876378321055821630297001325749245036289912107958940153069377468194744103504601932320545256459715588161660970567649651552877044037362412004154322533771653952212046361323367460781496181602061217473429286103209157240508012748157085209070303605553127018480721281454855721921722214168739106745792528135076119173289214747246633212451781484358230667954409728220358810295873322626391042138964776999523862047688471704988570394062354481372020258937355248604452513290325916340885174863929158922454672333407211491030644428915946870443123072766886435194740401704546967285019534904936421081918236597049627299829405067413566071646095700277786308230376887919195061958954699871900662599221565363144019569327332904589632046450066669943959398065933850869420755015998872600608412199464409174878530702899940178400959457118030274044291605668114926092558475141244759580381436181907163641477065016042238865131370467659646660493772072982124947517468539570851544584449542708553870453188316925666864431625985545292375440419673621382741314162484676596925158910572378097429554608175606357531751495674861", 10)

				goJWT.accessTokenVerifyKey = &rsa.PublicKey{
					N: modulus,
					E: 65537,
				}
			},
			assert: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &sswGoJWT{}

			if tt.modify != nil {
				tt.modify(g)
			}

			err := g.ValidateToken(tt.Params.signedToken, tt.Params.TokenType)

			tt.assert(t, err)
		})
	}
}

func TestGoJWT_ValidateAccessTokenWithClaims(t *testing.T) {
	type Params struct {
		signedToken string
		TokenType
	}
	tests := []struct {
		name   string
		Params Params
		modify func(goJWT *sswGoJWT)
		assert func(t *testing.T, claims jwt.MapClaims, err error)
	}{
		{
			name: "success_rs256_access_token",
			Params: Params{
				signedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjo5MjIzMzcxOTc0NzE5MTc5MDAwfQ.Dc1FOioAMAR_HAvvXHB1OST1K37SbIpsRAr6lSlSm0NL4wlcsTsNw9ogO3Yma2_mzo5WC7Ktb-tCm8q7_FpQd6K3f13ZrGH1KYen9JCZEYDKaqQtAalOtU8k2qk4hWfxTFh8uHuNxvLYzOXcZfYXyqYOdtkKECyj3UDLDFIV8SODcorGKiOnGhOK71b2GuBHp3JiTJhK-fDr1_EMrEdteea6tDlLBVSvhOItSZHY1G9nwWpnLgPUg4lHxQ3AkQ6hH1g8SDuridoPnFuNjpbmdPFW-A9cxM0IGvl1n4Sulj-xjFkC9BLTa3uIWTCokYZTeSQflk0AXy3Tl2JEgsMnIyXi-xOZRYaziPd2nUwHDmPgN7k5SwKh8ug9LG-32ye0V98dX3grOsKH-0stqt0YRvonXeGRkgA23V5WL77vC9P1xpzCFndhpvoWCTQuUQ6qUr0ixJRABWTYzrFdcTcxKmBYGP_gAx4XIGW6NzI9fCIilcshtCMRnKaQWuyeiIqvyEY_zoV8F5LJN_LrXioDoD2T8cvKS87zVr1z8xtmU3-8NRgLg5Rh--kmV4m02bTu2YC3IfXLQDaaoV0Rho2EYQSbC4o5iUIJ-qL4Rc8wZ189M-UyNsewbDUL2ngJ0oZyllqkbX32zJ6yEibSHO8B8C85NgVB6LwY_x7tkwwNp7I",
				TokenType:   AccessToken,
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodRS256

				modulus := &big.Int{}
				modulus.SetString("775022944367959914404878644861830075371315717976192822555668947583599028135341802475604042648740904113102863328517158687952274426150211668106179189511979855984876378321055821630297001325749245036289912107958940153069377468194744103504601932320545256459715588161660970567649651552877044037362412004154322533771653952212046361323367460781496181602061217473429286103209157240508012748157085209070303605553127018480721281454855721921722214168739106745792528135076119173289214747246633212451781484358230667954409728220358810295873322626391042138964776999523862047688471704988570394062354481372020258937355248604452513290325916340885174863929158922454672333407211491030644428915946870443123072766886435194740401704546967285019534904936421081918236597049627299829405067413566071646095700277786308230376887919195061958954699871900662599221565363144019569327332904589632046450066669943959398065933850869420755015998872600608412199464409174878530702899940178400959457118030274044291605668114926092558475141244759580381436181907163641477065016042238865131370467659646660493772072982124947517468539570851544584449542708553870453188316925666864431625985545292375440419673621382741314162484676596925158910572378097429554608175606357531751495674861", 10)

				goJWT.accessTokenVerifyKey = &rsa.PublicKey{
					N: modulus,
					E: 65537,
				}
			},
			assert: func(t *testing.T, claims jwt.MapClaims, err error) {
				assert.NoError(t, err)
				expected := jwt.MapClaims{
					"sub":   "1234567890",
					"name":  "John Doe",
					"admin": true,
					"iat":   float64(1516239022),
					"exp":   float64(9223371974719179000),
				}
				assert.EqualValues(t, expected, claims)
			},
		},
		{
			name: "success_hs256_access_token",
			Params: Params{
				signedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0aGlzIGlzIGEgdGVzdCBzdHJpbmciLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6OTIyMzM3MTk3NDcxOTE3OTAwMH0.DBa2dJSYEseCFIveAFbGMBKKRLzCJHfb8qyb9lfnQUo",
				TokenType:   AccessToken,
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.Config.Issuer = testString
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodHS256

				goJWT.accessTokenSecret = []byte(secret)
			},
			assert: func(t *testing.T, claims jwt.MapClaims, err error) {
				assert.NoError(t, err)
				expected := jwt.MapClaims{
					"iss": testString,
					"iat": float64(1516239022),
					"exp": float64(9223371974719179000),
				}
				assert.EqualValues(t, expected, claims)
			},
		},
		{
			name:   "error_not_initialized",
			Params: Params{},
			modify: func(goJWT *sswGoJWT) {},
			assert: func(t *testing.T, claims jwt.MapClaims, err error) {
				assert.ErrorIs(t, err, ErrorNotInitialized)
			},
		},
		{
			name: "error_expired_token",
			Params: Params{
				signedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxfQ.M_ybVRzvzc6o5aHGOL1ipU0TQtD75R34unxe2emL4RRxbqjqkK_dZeZzSpxbcGrGlvvoGrRsPqNGr2wAwFIUXUrDD3s3oRyWqBZYJLeyf6hKm0EHKkcP7UoUbfOeVdoye5dKOgB9WdDRPh_dxcKPC9tbn4akCj1o6zefiwg5C3l1o8lcE000ctfiVKFbQZfXEeOEPcIBXoEa9yMMLc9sGxpl9drRobdwLszts03dIw1ymqwOLm7hacDhI3Pe2bFlaxXb634sCx-VzuYdsjeEFebJXNXosMjGKRPmnS8I00YZkDhXDw68KHL2boDlyerNFbqxBfAkRRVjpV6yyDe9Rk1ZDKtVvWCuC5JblUYmyotn_kgtOwYFa1Gz1FdNVBNat_aNGQB_IP9-Z8En_f9FOLmqcECA9cykZH4jF2ezZIylh4SX8C0rAsHWJWd2BWp475V9t1SxRGB0vorlkWL-GlfMITpDBVqQSfQwoQrifehuNRRYr9m6kFdDnlBC_59MAFCghLX5pPAI4ni3dtxAG7Hr_P4Ja4U7izuVlF_C0kD0YuuTFoRS2NZJCP6UHHWf1NsYFIVs_Opc8rxk0LjJrsNYecHRdRwb5IxQ_ZZYNbsiXXi4OoliM_3OIuABZLIjDUqk1TqQOBh0loQQah83K0XxyStr44Q2xaqk_USVSnE",
				TokenType:   AccessToken,
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodRS256

				modulus := &big.Int{}
				modulus.SetString("775022944367959914404878644861830075371315717976192822555668947583599028135341802475604042648740904113102863328517158687952274426150211668106179189511979855984876378321055821630297001325749245036289912107958940153069377468194744103504601932320545256459715588161660970567649651552877044037362412004154322533771653952212046361323367460781496181602061217473429286103209157240508012748157085209070303605553127018480721281454855721921722214168739106745792528135076119173289214747246633212451781484358230667954409728220358810295873322626391042138964776999523862047688471704988570394062354481372020258937355248604452513290325916340885174863929158922454672333407211491030644428915946870443123072766886435194740401704546967285019534904936421081918236597049627299829405067413566071646095700277786308230376887919195061958954699871900662599221565363144019569327332904589632046450066669943959398065933850869420755015998872600608412199464409174878530702899940178400959457118030274044291605668114926092558475141244759580381436181907163641477065016042238865131370467659646660493772072982124947517468539570851544584449542708553870453188316925666864431625985545292375440419673621382741314162484676596925158910572378097429554608175606357531751495674861", 10)

				goJWT.accessTokenVerifyKey = &rsa.PublicKey{
					N: modulus,
					E: 65537,
				}
			},
			assert: func(t *testing.T, claims jwt.MapClaims, err error) {
				assert.ErrorIs(t, err, jwt.ErrTokenExpired)
			},
		},
		{
			name: "error_invalid_signature",
			Params: Params{
				signedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxfQ.a",
				TokenType:   AccessToken,
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodRS256

				modulus := &big.Int{}
				modulus.SetString("775022944367959914404878644861830075371315717976192822555668947583599028135341802475604042648740904113102863328517158687952274426150211668106179189511979855984876378321055821630297001325749245036289912107958940153069377468194744103504601932320545256459715588161660970567649651552877044037362412004154322533771653952212046361323367460781496181602061217473429286103209157240508012748157085209070303605553127018480721281454855721921722214168739106745792528135076119173289214747246633212451781484358230667954409728220358810295873322626391042138964776999523862047688471704988570394062354481372020258937355248604452513290325916340885174863929158922454672333407211491030644428915946870443123072766886435194740401704546967285019534904936421081918236597049627299829405067413566071646095700277786308230376887919195061958954699871900662599221565363144019569327332904589632046450066669943959398065933850869420755015998872600608412199464409174878530702899940178400959457118030274044291605668114926092558475141244759580381436181907163641477065016042238865131370467659646660493772072982124947517468539570851544584449542708553870453188316925666864431625985545292375440419673621382741314162484676596925158910572378097429554608175606357531751495674861", 10)

				goJWT.accessTokenVerifyKey = &rsa.PublicKey{
					N: modulus,
					E: 65537,
				}
			},
			assert: func(t *testing.T, claims jwt.MapClaims, err error) {
				assert.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &sswGoJWT{}

			if tt.modify != nil {
				tt.modify(g)
			}

			target := jwt.MapClaims{}
			err := g.ValidateAccessTokenWithClaims(tt.Params.signedToken, &target)

			tt.assert(t, target, err)
		})
	}
}

func TestGoJWT_RenewToken(t *testing.T) {
	timeNow = func() time.Time {
		return testTime
	}
	t.Cleanup(func() {
		timeNow = time.Now
	})

	type Params struct {
		signedTokens Tokens
	}
	tests := []struct {
		name string
		JWTConfig
		Params
		modify func(goJWT *sswGoJWT)
		assert func(t *testing.T, resp Tokens, err error)
	}{
		{
			name: "success_rs256",
			JWTConfig: JWTConfig{
				Issuer:             testString,
				AccessTokenMaxAge:  900,
				RefreshTokenMaxAge: 50000,
			},
			Params: Params{
				signedTokens: Tokens{
					AccessToken:  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0aGlzIGlzIGEgdGVzdCBzdHJpbmciLCJpYXQiOjE2ODAyODI1MDEsImV4cCI6MTY4MDM3MjUwMSwidXNlciI6InZlcnkgbmljZSJ9.u3OPU_zXSh4Rrlp2OAOnTPOroNgh6T5SI1ylfPKtBrujkIxL8WeXwSh2kbWk5FiPyZ9vTgsZZqnJZgb_iVFmQVdnCmE7hHsstaXAXN7GCTf3yXD-KYXlAjxDmkQfQngLhHTtpoN-4FCbScXtV_nmgHaDGNjvmcY3tFy997tqUlNG890LRhxDAfrtHCrW-3xdArfTLzzsdtj1-Co-cl1eyNURCtl9aBD5o1XB9Dzd6OCVhrLKsUzDL4YaR_q1-rHbQ4LvMChZ6nkmhMOdF3HSifR7qGeJa4caPGF5dyFyV4g5lZqGtiJ4WcQPwVMOad5ILb2ObxwvOU8vG0nAoF6f4mwZywIgXpFPphRklWy20MIOEukGC7wo6duHyGWmSRWM5Kli2PhjlMuJN2JaAuhiz_c8l5Prb6o6BLJ0r1Ucd0eq-1Z50-5PA2Y3wO1TPviS_R5EqUzQek7-zQ-YHYUaDBvN6oO-RsGvzmQHgpp9X0nOboQ_9npQIPHr--_wXE7HIJaLI6AQAQtZbW0gjOGDI7WFUQt3TkJ7S09x2XdN1qoxmHnhtsGNv_wUvgD_yrIl_KPyNBH_X7gIRiPORm0vTLv39Z_3FPHJqEE0xE_vngQKYCyv6yoNQo3HOcScxMoq9eoD4rBGurBSZbaahg4agvXID2mkpVfGwL-v3GgynFY",
					RefreshToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0aGlzIGlzIGEgdGVzdCBzdHJpbmciLCJpYXQiOjE2ODAyODI1MDEsImV4cCI6NTAxNjgwMzMyNTAxfQ.ZWktdVIzRrmoR3USoqvt0BRegzVNJC1yAI520bfr18jSI6z4etOdTliKboXZQw6d_Ypk0BI7rLTcmQyLhcHeH8xiLm5S6InIiqgKQpQjQc3PuL-v2wcI5THxgoWLX0dax_S5IpaNbX_LXWrXwi16_eeY2M8FQ7Ir4nRcu67rML7SCR_HocL3gBW-yjCSymMfEWLA6vAW0dOQnyLuJiXyaqtEclKnM5gHc-uz7G2wHd73W9wiLAaKpgUK_v9dFEWdsj_bDpkX0NA4DqIilZdooi6nbkhb0PWeepkiTCWXf54Nyq5NLHr1bcqrLs8nRbwrnIp-jW_5gJZ3BdV5gVbysC0G1WEmC85TK6goMb1oHfpbgDaIMk6bcBIt7f7rxTXcvsE3Y_JtjYHjezDcLlYhYCohoobBlS8Tuc1Fg2uJfTNh5mqvgRI86vWU8hcGWkFQcmtJ20LVPBqE0dSTzd1KaQJyjs1RWo-7bdRM6A7WqLPXWRkYzRdW27zJe2RPWl9_i12GWct6bqE0yi0rta1RmLWH9SQJ49L8ndYW1D1sfM-KUSL2Rz_nRLukh0CxQVOz3RPp6P_EQd5w-6gUrNZZmQbJD-ZMvIOahHzTqJ8tLzJA-CYG75vJ52E-C_9in847fVWXu8RllrbiDZAu00iF9MKENo3MWPKJOhfKtCc9LYo",
				},
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodRS256

				//  Access Token Signing & Verify Key
				{
					modulus := &big.Int{}
					modulus.SetString("775022944367959914404878644861830075371315717976192822555668947583599028135341802475604042648740904113102863328517158687952274426150211668106179189511979855984876378321055821630297001325749245036289912107958940153069377468194744103504601932320545256459715588161660970567649651552877044037362412004154322533771653952212046361323367460781496181602061217473429286103209157240508012748157085209070303605553127018480721281454855721921722214168739106745792528135076119173289214747246633212451781484358230667954409728220358810295873322626391042138964776999523862047688471704988570394062354481372020258937355248604452513290325916340885174863929158922454672333407211491030644428915946870443123072766886435194740401704546967285019534904936421081918236597049627299829405067413566071646095700277786308230376887919195061958954699871900662599221565363144019569327332904589632046450066669943959398065933850869420755015998872600608412199464409174878530702899940178400959457118030274044291605668114926092558475141244759580381436181907163641477065016042238865131370467659646660493772072982124947517468539570851544584449542708553870453188316925666864431625985545292375440419673621382741314162484676596925158910572378097429554608175606357531751495674861", 10)

					privExponent := &big.Int{}
					privExponent.SetString("21544511255438835630660869602882505439379923079577856130521733946819661607304324892454714614628344352198827631831436342875033217246868089130487726323947927139810803290323179237786228953343823584366299518470734533706662814147826794521692081628687815530059740030301244765742960315354936825438069400026984501418175863384118586385364322733220762727141744785902252484332461809858026985647052042918116200803366117457855268340995742599158606393026044259574128927284122095618313335475006351743570866852617146119519387875492068488904972991412180604394016553961363647108459557723703310032235217856268350830940868574228477610042009537478761880127469767920876502433637152458565154588313300083444952847678876180852588257840819629742690291583380639814275181976397709613211065381453927319496590791547277703347286281932463695191903523152114538086189257753745262158069923171291172859626656097604512910548456887056428502919183172072182361261253546505073359199768183750279932224988969620109323907460011376876564241897323373213494835640721883378638460298885886092469012194756278853677895387277843613077782156670713024903760025119565780244199200423563091384300597781854553879106733489389887055370009800990939971879939610835912169669380380510849393772223", 10)

					primes := make([]*big.Int, 2)
					prime1 := &big.Int{}
					prime2 := &big.Int{}
					prime1.SetString("31601391161334329981235175299355019049336918371188843222338191020826590093646970855614231742311629504348352786414252281925053011210180321126722760009788252127105301592692293462336507100584918402599009587288431426123235810966146444603352270828209034599455152881927423413709478193205519409155945019246118536551261733710667873194976556124003567790344571043819547409137705733652136093528070000203714708290218968049132829221443714341641543154920825683062440110674471178700340690457264743207232722113895048114424307992652739237416385382264002787251671914744339487002307015062501667400659858218668134729203863553661417592251", 10)
					prime2.SetString("24524962854047831772101125127790094528063177173049290064139053092373214109523148394819477077349894870902619147430768017901067987346805850761406893313019772823620494354858571252751147779176675515851556428522140340116213340262840696188570211177811487359886701033101247755171466808307182475849693175675010481148199855053330174755622779659393405623119550593681410967856500055351646491925884396593706629566451541425830582608142520558931201218068302709261514677674223368164260063234722885912850230007270690117850353567146838274814731131736962703311350605599191518707509645419568996664206241029653724225554265523491201685111", 10)
					primes[0] = prime1
					primes[1] = prime2

					dp := &big.Int{}
					dp.SetString("10464040001710732790985009066196244386982322437297543170544289231166483537882919793974158765886517110546158716724532535362552075869693808822054879151813706141726233270717540632408632384604014743653220425923466902334564297019643010731912471264216614429143480365148038749117435742721714095825154689147504743300714571665703396801870489104582166175111273574041045490725809117383844322530061599927076504640219140724083060361849795457954485679920302091156720827040400064833240662886813589153305114707625256559365273170095626809148618020057541915042625268502783331666647306618724517208015618401869435460250744510398804082723", 10)

					dq := &big.Int{}
					dq.SetString("23766802200641345250437379770069986321800211261387208161245333185066682962447543795159677871424831364662652313540069084409031981085234087427067354337293418859590173748743804550612297581569034876287413222025262907077236148335036322316131081406136768141870458966893409008326518279176609643769013889563080254943059966038910122967245347802733335131756805739586799700620018844552518735198511434946105280229410925850983812686356403607401613143121228822923051996486985982505765001084890751899095639989498585532978223070983762541339371483402448056060045292158784389652145278090883722891502549308548418134628941783457431835803", 10)

					qinv := &big.Int{}
					qinv.SetString("1502949234508924879857288338573911775227899437615874596418784932672315502648861724554229491856942481528382220643854876885371966489281641547657761847926093298089069459512523598896574192401038026865029272200157532262272478668155752778021130495882655365425738280105904514157010683772607216382381158180766384385966760431763738470397452165949080911355206809704047615211521575067649428011184518652523681697371267307914976300656063018878794371466780009848848010844381049796130584206887913219680249415144453642247772115060842979938234575367027622104982178695993844789151478041084892054220308665341004815564601171213629359958", 10)

					publicKey := rsa.PublicKey{
						N: modulus,
						E: 65537,
					}

					goJWT.accessTokenSigningKey = &rsa.PrivateKey{
						PublicKey: publicKey,
						D:         privExponent,
						Primes:    primes,
						Precomputed: rsa.PrecomputedValues{
							Dp:        dp,
							Dq:        dq,
							Qinv:      qinv,
							CRTValues: []rsa.CRTValue{},
						},
					}
					goJWT.accessTokenVerifyKey = &publicKey
				}
				// Refresh Token Signing & Verify Key
				{
					modulus := &big.Int{}
					modulus.SetString("819916210207963106248339561457160367534375955348566045978913574284599733129731887901816257373184343206273796910965368783816593980682979140467046323153757954553519717606060893170003911869615971925260797519018677238579292216323353755099193565639646071101889935448068769600679399081524685480464165241935636634596496416300745040937931378625560590461178905128563409635478272926777752864485934711535817828796582113128460615145009604780488008344227887417991179087413978225159328376657264248723197815821422279478048254809301546507874694609616361606655765131912309488177745199940604353789879872118160626875501716417233318131043542347892847387739074999149344361829304392676161884107662745326971479711203723138030889207123014199197126950624136720867681201324065861073058302878750449802189101144369201867295949454804971138832933635021773794498232108653321037553635869102070574969559397223092608724569780438024626673591493643467524275050173642594459895911635610086010432221617051426630889692282521721375272850323180037914720148638097877032782762163526334529363694728173863955049581861387357196690701611596485124473846446926659774125458593556272264913369200314469611095817896582492844921067314858553124261312747963982400866679110077700559238035117", 10)

					privExponent := &big.Int{}
					privExponent.SetString("51137639947282438878650044363583059985912716747596986632571055051166538126062820876736407708819308220633293328555944655749428992722304610169202921187893642358324486102732409186145093455102541850321246164136119187828140698143364946121548952493279419497825275968445017253502251304541436927253265719004713592991946215139986501591983070786456183736058543642720950560523329425945711046181336621044641277068007833550705445235595568297911786229260287926225474838942957962606447575256520249884127608407007698969536631849688268784822891102992307827138951126488724919250599409566462003084000396375833217302494976362290632587094407894282982846961956847148526224335727334713671448020760732397179938661117882992947469103841443424535386584212348391492819877835387292840024991073748478491105267430383705907868829870356985107715143284138572403799156053533714889899383430136988862912102407304937518694861563866630677918658617975115261410047975647324133120127125578418344703260874559742930566106621632598729561810145150215468794392876218175657417922627674202435386314429767092316965466493475246068712399701604891099469050355109157889525237921081442189673886168564457381718872900882469206512953721529254380553651614063286009750518919954783707978961473", 10)

					primes := make([]*big.Int, 2)
					prime1 := &big.Int{}
					prime2 := &big.Int{}
					prime1.SetString("29794695116749230965976364224673406030823069308363828136840701379212722638702488898212489736733300052360637637571182948072671923494723905666290722496531335194697247179522081947450739553183672198735264823214821930999107371292977983741267380719093641988068945223949756319624259502867086215531749485519411784930052073859680955974190377762130397320766767156117676237648192257272248543236259133663840651762516017557727711614825046043892822130415978425738501447730186198915594855559117723993815855382291641644998517129720482182124932735319785083058675420698938045976820672339534472229021050475806880106276347923044372691341", 10)
					prime2.SetString("27518865589835932590648263897646328449108275017978927178994247222625634128481002384454905242021107978328689785340494682087991214539365928285858017079404671825457380182570194150059398717869437654635321310255974584530246381289621894341813904679530056242541102141359326360874007509500112016437763427641351137138059183736194892531591034696220874629795600020374862156857709128215735658406135663595618793284460005515373485961573654232770471672095272886628321371972228709040051283479630890167332579852898871118865548251756239084154890402674370181622021128916992565745406024074302120663951778197671412931620989310268426885537", 10)
					primes[0] = prime1
					primes[1] = prime2

					dp := &big.Int{}
					dp.SetString("19610207575277752685008323097353973620085647719857084191870602163546405710063503953864164438317147531296460083565512252088357773775804746493056598789811543763420140639466026897833096580963084979361973360840004028161900856931544094613417893210218719916312219848865110378061132393246132168194485772279473081510563440589855166332708270820597444015308520397319620435951520103413925582686055781170785457280255861839153223988059849567470541565764274064943928772263630951832158690427430963035739306375255961706471322098821932632344461503242732037745639322395725965686713760186853524872954560206813399657967716979118955949173", 10)

					dq := &big.Int{}
					dq.SetString("16301706193359482597109076541470061329931650228466299798130730120756137659185161902004864217327394831051996941212964051493081510018185199716829665640382189820707872969893688259880007269540033539312252303707336333601137605639669054183625146426803109289472713252574776497371127661341270561883566375502695808430518206359618144143826521507108702194982293659932759716125041449634855203416412177361989538912104472193163325228285914495305674988567599665495389178999310849917785540664505699817909772306164347978206466267573011733282654227429193792225944524283143909241098891811291808147101635487864828482297353677961321650017", 10)

					qinv := &big.Int{}
					qinv.SetString("28138733744198538610167996567240892089898548500578617544368065810057920210024256159552043682996804019014760158040467784075155415105057682663169889780401844415465504426886182988462561011182361547855635443122638867588410602493856063465579581365916309183657112935136115963766735374866778033502270819024151574624059944640452436320400679093724386400626511733999488688498872874214069439665089040569038956730937420152950652717477944327898891604684007417657008662158577468973910384543491291258750009142255271120933927285343178640281091137587043828924980051200608894144285591778725275810560309411809996883150826117703056993162", 10)

					publicKey := rsa.PublicKey{
						N: modulus,
						E: 65537,
					}

					goJWT.refreshTokenSigningKey = &rsa.PrivateKey{
						PublicKey: publicKey,
						D:         privExponent,
						Primes:    primes,
						Precomputed: rsa.PrecomputedValues{
							Dp:        dp,
							Dq:        dq,
							Qinv:      qinv,
							CRTValues: []rsa.CRTValue{},
						},
					}
					goJWT.refreshTokenVerifyKey = &publicKey
				}
			},
			assert: func(t *testing.T, resp Tokens, err error) {
				const expectedAccessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODAyODM0MDEsImlhdCI6MTY4MDI4MjUwMSwiaXNzIjoidGhpcyBpcyBhIHRlc3Qgc3RyaW5nIiwidXNlciI6InZlcnkgbmljZSJ9.g6r5mZHRnrOmzTZ9gsWDyi5xH2OODCmyNKoY_MeidNLJxBNnczRhe4CLUSC_DT6_J6_Kf_nLka_PqB1GbHYr-e8J6oRrYaMm1QbF8OU38PQA0kvTsvFCLVOWQ-kDKuya7632Pu2czPDY4SvWIFdQ2wQxLk-Ac8EOo9Tjr1tWs_Dk05fDOdKqTPrA2qM3heUZ-nLCwlzbrTU7E2QCx7Kypec4qDo5Ue7TCJe53XA7EMe5LcqyQzfQ9kGt256mVcGeNM9MRMZDOJLncdyn2JETcR2Y7jIKWh7RBAA4W7vfYeZ-6isKPmyHC3foPMVP3F4JiwyazFsvVjUZwhSCDYY6QOavZ4ZhxkUILBi8br6xxORDoscg_EYGhJ7R2v7LTIxompHMsROj9VGpNktnkCJ-vdYY3tseywHcCSQUIxcjDrI6ZE-U4Pct2wRAmBrEXMtasNPD1aWQhVUcG7F0-i0Fr4Kd6zQ8QH87Sm3mUJR4cM20zqwKEPakEx-U-CujMKokVxnbH1UQoX2tzbkyioWVyc65xBYQnRRN4hwTbrde59voWxpOGu73KDlw5NvsZZ0f3oDGzvq-H179cDqMXcN8GvMCIX4nfh_iyN1ycNeJVblB5JdAjvR3vLW3ymjm8ESYaA9-x45hqEjsqNSrRJSGENf2T37DvbYjQ4zcNBck-vo"
				const expectedRefreshToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODAzMzI1MDEsImlhdCI6MTY4MDI4MjUwMSwiaXNzIjoidGhpcyBpcyBhIHRlc3Qgc3RyaW5nIn0.P3SmXd2-RNLEqs7FnxcVNfCGw_HPcJIyKf_GuMqHwsTxUGPrdeQFvOVOtxAEHCL3g9iPJXput4QjmogZY0Fz80LwNiJbIpcWCvc-T3QpKDY3XpUF44omh5nrthkRBPMVIhbhmnduijfEaA62iddQ4GvKlPkSvoUAo21nm1QMwJGhPijnwBrxluoQgppFY_qm-1qzQhOfPhjaIPqJjT6SJcB-xfu3Nkaxrtix3_fNBVhueClxZmRoiwe9ZEj7fsfcdGYdXffDti2OCsN849kkKCncyrodRJnjYeumJdw-Yh7gfeFRV42NQfqElpUbpe03zneUKSrQ9n4O3BLmqTfsjRKDgLeMOyAf6gCHRikS2Kt1STMmlNQaXb7vOmO62c3jBsauYIi7Dau3ff467EN22Eph3QDIgAYuNf3uMEqHNtbspB_CaFf2bKVUuPBS-kOSZn7cnJu0cXUMKIjQ_MpkdD2xh_nl-lswi3PTiriRNvj9dynZjfTNwFMyWyW0FOTiXVliEnhuPmocXStK-3SWw7EmetTavLuOdKgQOycWztK4N1ZGqE5TsVA6UtU9Rm7CPfbs5hZjHhckl5tTQ8NKVLe2Rkr7MUg20wJJZm6wRLZBCL4z5IzFllee4y3dOVhpTHmwRJVt9vSHjhsfTLnBtqBl41sYm8n0d2-IyIqYqoA"

				assert.EqualValues(t, expectedAccessToken, resp.AccessToken)
				assert.EqualValues(t, expectedRefreshToken, resp.RefreshToken)
				assert.NoError(t, err)
			},
		},
		{
			name: "success_hs256",
			JWTConfig: JWTConfig{
				Issuer:             testString,
				AccessTokenMaxAge:  900,
				RefreshTokenMaxAge: 50000,
			},
			Params: Params{
				signedTokens: Tokens{
					AccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0aGlzIGlzIGEgdGVzdCBzdHJpbmciLCJpYXQiOjE2ODAyODI1MDEsImV4cCI6MTY4MDM3MjUwMSwidXNlciI6InZlcnkgbmljZSJ9.JnD285nGorU-u4Z3euQbWt4uj0V9v75JeUpzfnN9xRA",
					RefreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0aGlzIGlzIGEgdGVzdCBzdHJpbmciLCJpYXQiOjE2ODAyODI1MDEsImV4cCI6NTAxNjgwMzMyNTAxfQ.acf7YW0rmuMKPDCXoYtYPb5hWMtAraYVw3nzfjaBJu8",
				},
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodHS256

				goJWT.accessTokenSecret = []byte(secret)
				goJWT.refreshTokenSecret = []byte(secret)

			},
			assert: func(t *testing.T, resp Tokens, err error) {
				const expectedAccessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODAyODM0MDEsImlhdCI6MTY4MDI4MjUwMSwiaXNzIjoidGhpcyBpcyBhIHRlc3Qgc3RyaW5nIiwidXNlciI6InZlcnkgbmljZSJ9.aGII4sMtp9_0a0vxUkVvC8KPrVxYZsSy5hOaQIk5WDU"
				const expectedRefreshToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODAzMzI1MDEsImlhdCI6MTY4MDI4MjUwMSwiaXNzIjoidGhpcyBpcyBhIHRlc3Qgc3RyaW5nIn0.cA-P1MX8wciqOsGs3r4U1uI06PEyY4y_Wn2uA3cYs_c"

				assert.EqualValues(t, expectedAccessToken, resp.AccessToken)
				assert.EqualValues(t, expectedRefreshToken, resp.RefreshToken)
				assert.NoError(t, err)
			},
		},
		{
			name: "error_hs256_refresh_token_expired",
			JWTConfig: JWTConfig{
				Issuer:             testString,
				AccessTokenMaxAge:  900,
				RefreshTokenMaxAge: 50000,
			},
			Params: Params{
				signedTokens: Tokens{
					AccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0aGlzIGlzIGEgdGVzdCBzdHJpbmciLCJpYXQiOjE2ODAyODI1MDEsImV4cCI6MTY4MDM3MjUwMSwidXNlciI6InZlcnkgbmljZSJ9.JnD285nGorU-u4Z3euQbWt4uj0V9v75JeUpzfnN9xRA",
					RefreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0aGlzIGlzIGEgdGVzdCBzdHJpbmciLCJpYXQiOjE2ODAyODI1MDEsImV4cCI6MX0.fi2iFwKZmpIK8RsNwK1_G0YmhBa85b8j44perxzhLB4",
				},
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodHS256

				goJWT.accessTokenSecret = []byte(secret)
				goJWT.refreshTokenSecret = []byte(secret)

			},
			assert: func(t *testing.T, resp Tokens, err error) {
				assert.ErrorIs(t, err, ErrorRefreshTokenExpired)
			},
		},
		{
			name: "error_hs256_invalid_signature_access_token",
			JWTConfig: JWTConfig{
				Issuer:             testString,
				AccessTokenMaxAge:  900,
				RefreshTokenMaxAge: 50000,
			},
			Params: Params{
				signedTokens: Tokens{
					AccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0aGlzIGlzIGEgdGVzdCBzdHJpbmciLCJpYXQiOjE2ODAyODI1MDEsImV4cCI6MTY4MDM3MjUwMSwidXNlciI6InZlcnkgbmljZSJ9.JnD285nGorU-u4Z3euQbWt4uj0V9v75JeUpzfnN9xRA",
					RefreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0aGlzIGlzIGEgdGVzdCBzdHJpbmciLCJpYXQiOjE2ODAyODI1MDEsImV4cCI6NTAxNjgwMzMyNTAxfQ.acf7YW0rmuMKPDCXoYtYPb5hWMtAraYVw3nzfjaBJu8",
				},
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodHS256

				goJWT.refreshTokenSecret = []byte(secret)

			},
			assert: func(t *testing.T, resp Tokens, err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "error_hs256_invalid_signature_refresh_token",
			JWTConfig: JWTConfig{
				Issuer:             testString,
				AccessTokenMaxAge:  900,
				RefreshTokenMaxAge: 50000,
			},
			Params: Params{
				signedTokens: Tokens{
					AccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0aGlzIGlzIGEgdGVzdCBzdHJpbmciLCJpYXQiOjE2ODAyODI1MDEsImV4cCI6MTY4MDM3MjUwMSwidXNlciI6InZlcnkgbmljZSJ9.JnD285nGorU-u4Z3euQbWt4uj0V9v75JeUpzfnN9xRA",
					RefreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0aGlzIGlzIGEgdGVzdCBzdHJpbmciLCJpYXQiOjE2ODAyODI1MDEsImV4cCI6NTAxNjgwMzMyNTAxfQ.acf7YW0rmuMKPDCXoYtYPb5hWMtAraYVw3nzfjaBJu8",
				},
			},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.signingMethod = jwt.SigningMethodHS256

				goJWT.accessTokenSecret = []byte(secret)
			},
			assert: func(t *testing.T, resp Tokens, err error) {
				assert.Error(t, err)
			},
		},
		{
			name:      "error_not_initialized",
			JWTConfig: JWTConfig{},
			Params:    Params{},
			modify:    func(goJWT *sswGoJWT) {},
			assert: func(t *testing.T, resp Tokens, err error) {
				assert.ErrorIs(t, err, ErrorNotInitialized)
			},
		},
		{
			name:      "error_mode_validation_only",
			JWTConfig: JWTConfig{},
			Params:    Params{},
			modify: func(goJWT *sswGoJWT) {
				goJWT.initialized = true
				goJWT.mode = ModeValidationOnly
			},
			assert: func(t *testing.T, resp Tokens, err error) {
				assert.ErrorIs(t, err, ErrorValidationOnly)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &sswGoJWT{
				Config: tt.JWTConfig,
			}

			if tt.modify != nil {
				tt.modify(g)
			}

			resp, err := g.RenewToken(tt.Params.signedTokens)

			tt.assert(t, resp, err)
		})
	}
}
