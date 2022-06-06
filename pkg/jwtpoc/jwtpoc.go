package jwtpoc

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
)

// Options for scrypt
type Option func(c *Config)
type Config struct {
	log    *logrus.Logger
	secret []byte
}

type CustomClaims struct {
	UserId string `json:"userid"`
	jwt.StandardClaims
}

func New(opts ...func(*Config)) (*Config, error) {
	config := &Config{}

	// Set up default logger
	config.log = logrus.New()

	// apply options
	for _, opt := range opts {
		opt(config)
	}

	return config, nil
}

func SetLog(log *logrus.Logger) Option {
	return func(c *Config) {
		c.log = log
	}
}

func SetSecret(secret string) Option {
	return func(c *Config) {
		c.secret = []byte(secret)
	}
}

func (c *Config) Create(userid string) (string, error) {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &CustomClaims{
		UserId: userid,
		StandardClaims: jwt.StandardClaims{
			// Set the token expiration to 1 day
			ExpiresAt: jwt.TimeFunc().Add(24 * time.Hour).Unix(),
			Issuer:    "FindYourVote",
			IssuedAt:  jwt.TimeFunc().Unix(),
		},
	})

	// Sign and get the complete encoded token as a string using the secret
	return token.SignedString(c.secret)
}

func (c *Config) Validate(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return c.secret, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}
