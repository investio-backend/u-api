package service

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
	"gitlab.com/investio/backend/user-api/v1/schema"
)

type RedisService interface {
	TestConnection() (err error)
	BlockTokens(userID string, td *schema.TokenDetail) (err error)
	ReadBlockAuth(detail *schema.AuthDetail) (userID string, err error)
}

type redisService struct {
	client *redis.Client
	rctx   context.Context
}

func NewRedisService(redisCtx context.Context) RedisService {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	//Initializing redis
	dsn := os.Getenv("REDIS_HOST")
	pwd := os.Getenv("REDIS_PWD")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}

	return &redisService{
		client: redis.NewClient(&redis.Options{
			Addr:     dsn, //redis port
			Password: pwd,
			DB:       0, // use default DB
		}),
		rctx: redisCtx,
	}
}

func (s *redisService) TestConnection() (err error) {
	_, err = s.client.Ping(s.rctx).Result()
	return // return err
}

func (s *redisService) BlockTokens(userID string, td *schema.TokenDetail) (err error) {
	accessExp := time.Unix(td.AtExpires, 0) //converting Unix to UTC(to Time object)
	refreshExp := time.Unix(td.RtExpires, 0)
	now := time.Now()

	if err = s.client.Set(s.rctx, td.AccessUuid, userID, accessExp.Sub(now)).Err(); err != nil {
		return
	}

	if err = s.client.Set(s.rctx, td.RefreshUuid, userID, refreshExp.Sub(now)).Err(); err != nil {
		return
	}
	return
}

func (s *redisService) ReadBlockAuth(detail *schema.AuthDetail) (userID string, err error) {
	userID, err = s.client.Get(s.rctx, detail.ID).Result()
	return
}
