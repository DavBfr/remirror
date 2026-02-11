package main

import (
	"flag"
	"log"

	"remirror/internal/remirror"
)

func main() {
	configPath := flag.String("config", "remirror.hcl", "Path to config file")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()

	if flag.NArg() > 0 {
		log.Fatalf("Unhandled arguments: %v", flag.Args())
	}

	if err := remirror.Run(*configPath, *verboseFlag); err != nil {
		log.Fatal(err)
	}
}
