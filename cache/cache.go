package cache

import (
	"log"
	"os"

	"github.com/redis/go-redis/v9"
)

var rdb *redis.Client

func Client() *redis.Client {
	return rdb
}

func Connect() {

	cacheAddr := os.Getenv("CACHE_ADDR")
	cachePasswd := os.Getenv("CACHE_PASSWD")

	if cacheAddr == "" || cachePasswd == "" {
		log.Fatalln("missing cache addr or password")
	}

	rdb = redis.NewClient(&redis.Options{
		Addr:     cacheAddr,
		Password: cachePasswd,
		DB:       0,
	})
}
