package controllers

import (
	"fmt"
	"lenslocked.com/views"
	"net/http"
)

type Users struct {
	NewView *views.View
}

func NewUsers() *Users {
	return &Users{
		NewView: views.NewView("bootstrap", "users/new"),
	}
}

// New is used to render the form where a user can
// GET /signup
func (u *Users) New(w http.ResponseWriter, r *http.Request) {
	if err := u.NewView.Render(w, nil); err != nil {
		panic(err)
	}
}

// Create is used to process the signup form
// POST /signup
func (u *Users) Create(w http.ResponseWriter, r *http.Request) {
	var form SignupForm
	if err := ParseForm(r, &form); err != nil {
		panic(err)
	}

	fmt.Fprintln(w, form)
}

type SignupForm struct {
	Email    string `schema:"email"`
	Password string `schema:"password"`
}
