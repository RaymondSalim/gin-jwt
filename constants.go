package ssw_go_jwt

const (
	SigningAlgorithmRS256 = "RS256"
	SigningAlgorithmHS256 = "HS256"
)

const (
	AccessToken = iota
	RefreshToken
)

type Mode int

const (
	ModeFull Mode = iota
	ModeValidationOnly
)
