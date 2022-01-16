package main

import (
	"lenslocked.com/controllers"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {

	staticC := controllers.NewStatic()
	userC := controllers.NewUsers()

	r := mux.NewRouter()
	r.Handle("/", staticC.Home).Methods("GET")
	r.Handle("/contact", staticC.Contact).Methods("GET")
	r.HandleFunc("/signup", userC.New).Methods("GET")
	r.HandleFunc("/signup", userC.Create).Methods("POST")

	if err := http.ListenAndServe(":3000", r); err != nil {
		panic(err)
	}
}
