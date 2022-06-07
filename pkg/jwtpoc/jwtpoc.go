package jwtpoc

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

// Options for jwtpoc
type Option func(c *Config)

// Config for jwtpoc
type Config struct {
	log    *logrus.Logger
	secret []byte
}

// CustomClaims is a struct that contains the custom claims for the JWT
type CustomClaims struct {
	UserId string `json:"userid"`
	jwt.RegisteredClaims
}

// New creates a new jwtpoc config
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

// SetLogger sets the logger for the jwtpoc
func SetLog(log *logrus.Logger) Option {
	return func(c *Config) {
		c.log = log
	}
}

// SetSecret sets the secret for the jwtpoc
func SetSecret(secret string) Option {
	return func(c *Config) {
		c.secret = []byte(secret)
	}
}

// CreateToken creates a new JWT token
func (c *Config) Create(userid string) (string, error) {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &CustomClaims{
		UserId: userid,
		RegisteredClaims: jwt.RegisteredClaims{
			// Set the token expiration to 1 day
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			Issuer:    "FindYourVote",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})

	// Sign and get the complete encoded token as a string using the secret
	return token.SignedString(c.secret)
}

// ValidateToken validates a JWT token
func (c *Config) Validate(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
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
