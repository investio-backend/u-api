package service

import (
	log "github.com/sirupsen/logrus"
	"gitlab.com/investio/backend/user-api/db"
	"gitlab.com/investio/backend/user-api/v1/model"
)

type UserService interface {
	Create(newUser *model.User) (err error)
	GetByUsername(user *model.User, username string) (err error)
	GetUserData(userData *model.UserData, userID uint) (err error)
	GetRiskScore(userID uint) (score uint8, err error)
	SetRiskScore(userID uint, score uint8) (err error)
}

type userService struct {
}

func NewUserService() UserService {
	return &userService{}
}

func (s *userService) Create(newUser *model.User) (err error) {
	log.Info("New User ", newUser)
	if err = db.UserDB.Create(newUser).Error; err != nil {
		return
	}
	// if err = db.UserDB.Save(newUser).Error; err != nil {
	// 	return
	// }
	// err = db.UserDB.Session(&gorm.Session{FullSaveAssociations: true}).Updates(&newUser).Error

	ud := model.UserData{
		UserID: newUser.ID,
	}

	err = db.UserDB.Create(&ud).Error
	return
}

func (s *userService) GetByUsername(user *model.User, username string) (err error) {
	err = db.UserDB.Where("name = ?", username).First(&user).Error
	return
}

func (s *userService) GetUserData(userData *model.UserData, userID uint) (err error) {
	if err = db.UserDB.Where("user_id = ?", userID).First(&userData).Error; err != nil {
		return
	}
	return
}

func (s *userService) GetRiskScore(userID uint) (score uint8, err error) {
	var userData model.UserData
	if err = db.UserDB.Where("user_id = ?", userID).First(&userData).Error; err != nil {
		return
	}
	score = userData.RiskScore
	return
}

func (s *userService) SetRiskScore(userID uint, score uint8) (err error) {
	var userData model.UserData
	if err = db.UserDB.Where("user_id = ?", userID).First(&userData).Error; err != nil {
		return
	}
	userData.RiskScore = score

	err = db.UserDB.Save(&userData).Error
	return
}
