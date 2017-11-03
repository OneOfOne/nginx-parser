package main

import (
	"fmt"
	"log"
	"os"

	"github.com/OneOfOne/nginx-parser/ngparser"
)

func main() {
	f, err := os.Open("access.log")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	p := ngparser.New()
	p.Parse(f, func(r *ngparser.Record) {
		// if you wanna do some processing to the record
	})
	fmt.Printf("%+v\n", p.Stats(ngparser.IPs, 1000))
	fmt.Println(p.IPsCount())
}
