package main

import (
	"fmt"
	"lenslocked.com/rand"
)

func main() {
	fmt.Println(rand.String(10))
	fmt.Println(rand.RememberToken())
}
