package main

import (
	"os"

	"github.com/lynch1981/curlu/internal/curlu"
)

var version = "dev"

func main() {
	os.Exit(curlu.Run(os.Args[1:], os.Stdout, os.Stderr, version))
}
