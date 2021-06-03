package model

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID         uint           `gorm:"primaryKey" json:"uid"`
	Name       string         `gorm:"unique" json:"username"`
	Email      string         `gorm:"unique" json:"email"`
	IsValidate bool           `gorm:"default:false" json:"is_validate"`
	HashPwd    string         `json:"-"`
	UserData   UserData       `json:"data"`
	CreatedAt  time.Time      `json:"-"`
	UpdatedAt  time.Time      `json:"-"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
}

func (User) TableName() string {
	return "user"
}

type UserData struct {
	ID            uint           `gorm:"primaryKey" json:"-"`
	RiskScore     uint8          `json:"risk_score"`
	RiskUpdatedAt time.Time      `json:"risk_last_updated"`
	UserID        uint           `json:"-"`
	CreatedAt     time.Time      `json:"-"`
	UpdatedAt     time.Time      `json:"-"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
}

func (UserData) TableName() string {
	return "user_data"
}
