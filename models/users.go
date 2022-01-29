package models

import (
	"errors"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"golang.org/x/crypto/bcrypt"
	"lenslocked.com/hash"
	"lenslocked.com/rand"
)

const (
	userPwPepper  = "secret-random-string"
	hmacSecretKey = "secret-hmac-key"
)

var (
	// ErrNotFound is returned when a resource cannot be found in the database.
	ErrNotFound        = errors.New("models: resource not found")
	ErrInvalidID       = errors.New("models: ID provided was invalid")
	ErrInvalidPassword = errors.New("models: Incorrect password provided")
)

type UserDB interface {
	ByID(id uint) (*User, error)
	ByEmail(email string) (*User, error)
	ByRemember(token string) (*User, error)

	Create(user *User) error
	Update(user *User) error
	Delete(id uint) error

	Close() error
	AutoMigrate() error
	DestructiveReset() error
}

type UserService interface {
	UserDB
	Authenticate(email, password string) (*User, error)
}

type User struct {
	gorm.Model
	Name         string
	Email        string `gorm:"not null;unique_index"`
	Password     string `gorm:"-"`
	PasswordHash string `gorm:"not null"`
	Remember     string `gorm:"-"`
	RememberHash string `gorm:"not null;unique_index"`
}

var _ UserDB = &userGorm{}

type userGorm struct {
	db   *gorm.DB
	hmac hash.HMAC
}

func newUserGorm(connectionInfo string) (*userGorm, error) {
	db, err := gorm.Open("postgres", connectionInfo)
	if err != nil {
		return nil, err
	}
	db.LogMode(true)
	hmac := hash.NewHMAC(hmacSecretKey)
	return &userGorm{db: db, hmac: hmac}, nil
}

// Close closes the UserService database connection
func (ug *userGorm) Close() error {
	return ug.db.Close()
}

func (ug *userGorm) AutoMigrate() error {
	return ug.db.AutoMigrate(&User{}).Error
}

// DestructiveReset drops the user table and rebuilds it
func (ug *userGorm) DestructiveReset() error {
	if err := ug.db.DropTableIfExists(&User{}).Error; err != nil {
		return err
	}
	return ug.AutoMigrate()
}

// Create saves provided user to storage and fills storage related data such as ID
func (ug *userGorm) Create(user *User) error {
	pwBytes := []byte(user.Password + userPwPepper)
	hashedBytes, err := bcrypt.GenerateFromPassword(pwBytes, bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = ""
	user.PasswordHash = string(hashedBytes)
	if user.Remember == "" {
		token, err := rand.RememberToken()
		if err != nil {
			return err
		}
		user.Remember = token
	}

	user.RememberHash = ug.hmac.Hash(user.Remember)

	return ug.db.Create(user).Error
}

// Update updates the provided user with all the data in the provided user object.
func (ug *userGorm) Update(user *User) error {
	if user.Remember != "" {
		user.RememberHash = ug.hmac.Hash(user.Remember)
	}
	return ug.db.Save(user).Error
}

// Delete deletes the user with the provided id
// returns ErrInvalidID error if provided id is zero
func (ug *userGorm) Delete(id uint) error {
	if id == 0 {
		return ErrInvalidID
	}
	return ug.db.Delete(&User{Model: gorm.Model{ID: id}}).Error
}

// ByID looks up a user with provided id
// If the user is found, returns user
// If the user not found, returns ErrNotFound
func (ug *userGorm) ByID(id uint) (*User, error) {
	var user User
	db := ug.db.Where("id = ?", id)
	if err := first(db, user); err != nil {
		return nil, err
	}

	return &user, nil
}

// ByEmail looks up a user with provided id
// If the user is found, returns user
// If the user not found, returns ErrNotFound
func (ug *userGorm) ByEmail(email string) (*User, error) {
	var user User
	db := ug.db.Where("email = ?", email)
	if err := first(db, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (ug *userGorm) ByRemember(token string) (*User, error) {
	var user User
	rememberHash := ug.hmac.Hash(token)
	db := ug.db.Where("remember_hash = ?", rememberHash)
	if err := first(db, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

type userValidator struct {
	UserDB
}

func (uv *userValidator) ByID(id uint) (*User, error) {
	// Validate the ID
	if id <= 0 {
		return nil, errors.New("Invalid ID")
	}
	// If it is valid, call the next method in the chain and // return its results.
	return uv.UserDB.ByID(id)
}

// NewUserService returns UserService
func NewUserService(connectionInfo string) (UserService, error) {
	ug, err := newUserGorm(connectionInfo)
	if err != nil {
		return nil, err
	}
	return &userService{
		UserDB: &userValidator{
			UserDB: ug,
		},
	}, nil
}

type userService struct {
	UserDB
}

func (us *userService) Authenticate(email, password string) (*User, error) {
	user, err := us.UserDB.ByEmail(email)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password+userPwPepper))
	switch err {
	case nil:
		return user, nil
	case bcrypt.ErrMismatchedHashAndPassword:
		return nil, ErrInvalidPassword
	default:
		return nil, err
	}

}

func first(db *gorm.DB, dst interface{}) error {
	err := db.First(dst).Error
	if err == gorm.ErrRecordNotFound {
		return ErrNotFound
	}
	return err
}
