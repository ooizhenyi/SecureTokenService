package token

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ooizhenyi/SecureTokenService/internal/config"
)

type TokenType string

const (
	AccessToken       string = "access"
	RefreshToken      string = "refresh"
	HMACSigningMethod string = "HS256"
	RSASigningMethod  string = "RS256"
)

type Claims struct {
	UserID    string    `json:"uid"`
	TokenType TokenType `json:"tokenType"`
	Roles     []string  `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

type JWTService struct {
	accessKeySecret     []byte
	refreshKeySecret    []byte
	privateKey          *rsa.PrivateKey
	publicKey           *rsa.PublicKey
	accessTokenExpiry   time.Duration
	refreshTokenExpiry  time.Duration
	signingMethod       jwt.SigningMethod
	tokenRevocationList map[string]bool
}

func NewJwtService(config config.Config) (*JWTService, error) {
	service := &JWTService{
		accessTokenExpiry:   config.AccessTokenExpiry,
		refreshTokenExpiry:  config.RefreshTokenExpiry,
		tokenRevocationList: make(map[string]bool),
	}

	switch config.SigningMethod {
	case HMACSigningMethod:
		service.accessKeySecret = []byte(config.AccessSecret)
		service.refreshKeySecret = []byte(config.RefreshSecret)
		service.signingMethod = jwt.SigningMethodHS256
	case RSASigningMethod:
		var err error
		service.privateKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(config.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
		service.publicKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(config.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("invalid public key: %w", err)
		}
		service.signingMethod = jwt.SigningMethodRS256
	default:
		return nil, fmt.Errorf("unsupported signing method: %s", config.SigningMethod)
	}

	return service, nil
}
