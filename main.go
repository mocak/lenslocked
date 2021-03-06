package main

import (
	"fmt"
	"lenslocked.com/controllers"
	"lenslocked.com/middleware"
	"lenslocked.com/models"
	"net/http"

	"github.com/gorilla/mux"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "ubms"
	password = "ubms"
	dbname   = "lenslocked_dev"
)

func main() {

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	services, err := models.NewServices(psqlInfo)
	if err != nil {
		panic(err)
	}
	defer services.Close()
	services.AutoMigrate()

	r := mux.NewRouter()

	staticC := controllers.NewStatic()
	userC := controllers.NewUsers(services.User)
	galleryC := controllers.NewGalleries(services.Gallery, r)

	userMw := middleware.User{
		UserService: services.User,
	}
	requireUserMw := middleware.RequireUser{}

	newGallery := requireUserMw.Apply(galleryC.New)
	createGallery := requireUserMw.ApplyFn(galleryC.Create)

	r.Handle("/", staticC.Home).Methods("GET")
	r.Handle("/contact", staticC.Contact).Methods("GET")
	r.HandleFunc("/signup", userC.New).Methods("GET")
	r.HandleFunc("/signup", userC.Create).Methods("POST")
	r.Handle("/login", userC.LoginView).Methods("GET")
	r.HandleFunc("/login", userC.Login).Methods("POST")
	r.HandleFunc("/cookietest", userC.CookieTest).Methods("GET")
	r.Handle("/galleries/new", newGallery).Methods("GET")
	r.Handle("/galleries", createGallery).Methods("POST")
	r.HandleFunc("/galleries/{id:[0-9]+}", galleryC.Show).
		Methods("GET").
		Name(controllers.ShowGallery)
	r.HandleFunc("/galleries/{id:[0-9]+}/edit",
		requireUserMw.ApplyFn(galleryC.Edit)).
		Methods("GET").
		Name(controllers.EditGallery)
	r.HandleFunc("/galleries/{id:[0-9]+}/update",
		requireUserMw.ApplyFn(galleryC.Update)).Methods("POST")
	r.HandleFunc("/galleries/{id:[0-9]+}/delete",
		requireUserMw.ApplyFn(galleryC.Delete)).Methods("POST")
	r.HandleFunc("/galleries",
		requireUserMw.ApplyFn(galleryC.Index)).
		Methods("GET").
		Name(controllers.IndexGalleries)

	if err := http.ListenAndServe(":3000", userMw.Apply(r)); err != nil {
		panic(err)
	}
}
