package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

type Config struct {
	PostgresConnectionString string

	RedisConnectionString string

	ServerPort int

	AccessSecret       string
	RefreshSecret      string
	PrivateKey         string
	PublicKey          string
	SigningMethod      string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration

	EnableRateLimiting bool
	MaxRequestsPerMin  int
}

func LoadConfig() *Config {
	config := &Config{
		ServerPort: getEnvAsInt("SERVER_PORT", 8080),

		RedisConnectionString: getEnv("REDIS_URL", "redis://localhost:6379/0"),

		PostgresConnectionString: getEnv("POSTGRES_CONN_STR",
			"postgres://postgres:password@localhost:5432/tokenservice?sslmode=disable"),

		AccessSecret:       getEnv("ACCESS_SECRET", "your-very-strong-access-secret-key"),
		RefreshSecret:      getEnv("REFRESH_SECRET", "your-very-strong-refresh-secret-key"),
		SigningMethod:      getEnv("SIGNING_METHOD", "HS256"),
		AccessTokenExpiry:  getEnvAsDuration("ACCESS_TOKEN_EXPIRY", 15*time.Minute),
		RefreshTokenExpiry: getEnvAsDuration("REFRESH_TOKEN_EXPIRY", 24*time.Hour),

		EnableRateLimiting: getEnvAsBool("ENABLE_RATE_LIMITING", true),
		MaxRequestsPerMin:  getEnvAsInt("MAX_REQUESTS_PER_MIN", 60),
	}

	if config.SigningMethod == "RS256" {
		config.PrivateKey = getEnv("PRIVATE_KEY_PATH", "")
		config.PublicKey = getEnv("PUBLIC_KEY_PATH", "")
	}

	return config
}

func getEnv(key, defaultValue string) string {
	if value, exist := os.LookupEnv(key); exist {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueString := getEnv(key, "")
	if valueString == "" {
		return defaultValue
	}

	value, err := strconv.Atoi(valueString)
	if err != nil {
		log.Printf("Warning: Environment variable %s with value '%s' cannot be parsed as an integer. Using default value %d. Error: %v",
			key, valueString, defaultValue, err)
		return defaultValue
	}

	return value
}

func getEnvAsBool(key string, defaultValue bool) bool {
	valueString := getEnv(key, "")
	if valueString == "" {
		return defaultValue
	}

	value, err := strconv.ParseBool(valueString)
	if err != nil {
		log.Printf("Warning: Environment variable %s with value '%s' cannot be parsed as an boolean. Using default value %t. Error: %v",
			key, valueString, defaultValue, err)
		return defaultValue
	}

	return value
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueString := getEnv(key, "")
	if valueString == "" {
		return defaultValue
	}

	value, err := time.ParseDuration(valueString)
	if err != nil {
		log.Printf("Warning: Environment variable %s with value '%s' cannot be parsed as an duration. Using default value %d. Error: %v",
			key, valueString, defaultValue, err)
		return defaultValue
	}

	return value
}
