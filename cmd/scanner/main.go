package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"dns-radar/internal/config"
	"dns-radar/internal/scanner"
	"dns-radar/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Value)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	s, err := scanner.New(cfg)
	if err != nil {
		log.Fatalf("scanner init error: %v", err)
	}

	if err := s.Run(ctx); err != nil {
		log.Fatalf("scan failed: %v", err)
	}
}
