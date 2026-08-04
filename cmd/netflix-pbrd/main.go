package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/w0s1nsk1/netflix-pbrd/internal/pbr"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "/etc/netflix-pbrd.json", "path to JSON configuration")
	showVersion := flag.Bool("version", false, "print version")
	checkConfig := flag.Bool("check", false, "validate configuration and exit")
	flag.Parse()
	if *showVersion {
		log.Print(version)
		return
	}
	config, err := pbr.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *checkConfig {
		log.Print("configuration is valid")
		return
	}
	runtime, err := pbr.NewRuntime(config)
	if err != nil {
		log.Fatalf("runtime: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() { <-signals; cancel() }()
	log.Printf("netflix-pbrd %s starting as %s", version, config.Role)
	if err := runtime.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
