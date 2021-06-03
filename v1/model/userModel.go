package model

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Name       string `gorm:"unique"`
	Email      string `gorm:"unique"`
	IsValidate bool   `gorm:"default:false"`
	HashPwd    string
	UserData   UserData
}

func (User) TableName() string {
	return "user"
}

type UserData struct {
	gorm.Model
	RiskScore uint8
	UserID    uint
}

func (UserData) TableName() string {
	return "user_data"
}
