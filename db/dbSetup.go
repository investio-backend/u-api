package db

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"gitlab.com/investio/backend/user-api/v1/model"
	"gorm.io/driver/mysql"

	"gorm.io/gorm"
)

var (
	UserDB *gorm.DB
)

type MariaDbConfig struct {
	Host     string
	Port     uint64
	User     string
	DbName   string
	Password string
}

func SetupDB() (err error) {
	UserDB, err = gorm.Open(
		mysql.Open(
			mySqlURL(buildDbConfig(
				os.Getenv("MYSQL_HOST"),
				os.Getenv("MYSQL_PORT"),
				os.Getenv("MYSQL_USER"),
				os.Getenv("MYSQL_PWD"),
				os.Getenv("MYSQL_DB"),
			)),
		),
		&gorm.Config{},
	)

	if err != nil {
		log.Fatalln("Database Init error: ", err)
		return
	}
	UserDB.AutoMigrate(&model.User{})

	// InfluxClient = influxdb2.NewClient(
	// 	os.Getenv("INFLUX_HOST"),
	// 	os.Getenv("INFLUX_TOKEN"),
	// )
	// InfluxQuery = db.InfluxClient.QueryAPI(os.Getenv("INFLUX_ORG"))

	return
}

func buildDbConfig(host string, port string, user, pwd, dbName string) *MariaDbConfig {
	portUint, err := strconv.ParseUint(port, 10, 32)
	if err != nil {
		log.Fatalln("Failed Build DB Config: ", err)
	}
	dbConfig := MariaDbConfig{
		Host:     host,
		Port:     portUint,
		User:     user,
		Password: pwd,
		DbName:   dbName,
	}
	return &dbConfig
}

func mySqlURL(dbConfig *MariaDbConfig) string {
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		dbConfig.User,
		dbConfig.Password,
		dbConfig.Host,
		dbConfig.Port,
		dbConfig.DbName,
	)
}
