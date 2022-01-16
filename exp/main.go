package main

import (
	"html/template"
	"os"
)

func main() {
	var err error
	t, err := template.ParseFiles("hello.gohtml")
	if err != nil {
		panic(err)
	}

	data := struct {
		Name string
	}{"Test"}

	t.Execute(os.Stdout, data)
}
