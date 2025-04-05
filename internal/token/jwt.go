package token

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/ooizhenyi/SecureTokenService/internal/config"
)

type TokenType string

const (
	AccessToken       string = "access"
	RefreshToken      string = "refresh"
	HMACSigningMethod string = "HS256"
	RSASigningMethod  string = "RS256"
	Issuer            string = "localhost:8080/auth"
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

func generateTokenID() string {
	return uuid.New().String()
}

func (j *JWTService) GenerateToken(userId string, roles []string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:    userId,
		Roles:     roles,
		TokenType: TokenType(AccessToken),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(j.accessTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    Issuer,
			Subject:   userId,
			ID:        generateTokenID(),
		},
	}
	token := jwt.NewWithClaims(j.signingMethod, claims)

	var tokenString string
	var err error
	switch j.signingMethod {
	case jwt.SigningMethodHS256:
		if claims.TokenType == TokenType(AccessToken) {
			tokenString, err = token.SignedString(j.accessKeySecret)
			if err != nil {
				return "", err
			}
		} else {
			tokenString, err = token.SignedString(j.refreshKeySecret)
			if err != nil {
				return "", err
			}
		}
	case jwt.SigningMethodRS256:
		tokenString, err = token.SignedString(j.privateKey)
		if err != nil {
			return "", err
		}
	default:
		return "", errors.New("unsupported signing method")
	}

	return tokenString, nil

}

//refresh token
//revoke token
//validate token
