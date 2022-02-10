package controllers

import (
	"fmt"
	"lenslocked.com/models"
	"lenslocked.com/views"
	"net/http"
)

type Galleries struct {
	gs  models.GalleryService
	New *views.View
}

func NewGalleries(gs models.GalleryService) *Galleries {
	return &Galleries{
		gs:  gs,
		New: views.NewView("bootstrap", "galleries/new"),
	}
}

//func (g *Galleries) New(w http.ResponseWriter, r *http.Request) {
//	g.New.Render(w, nil)
//}

func (g *Galleries) Create(w http.ResponseWriter, r *http.Request) {
	var vd views.Data
	var form GalleryForm

	if err := parseForm(r, &form); err != nil {
		vd.SetAlert(err)
		g.New.Render(w, vd)
		return
	}

	gallery := models.Gallery{
		Title: form.Title,
	}

	if err := g.gs.Create(&gallery); err != nil {
		vd.SetAlert(err)
		g.New.Render(w, vd)
		return
	}

	fmt.Fprintln(w, gallery)
}

type GalleryForm struct {
	Title string `schema:"title"`
}
