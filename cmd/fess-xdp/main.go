package main

import (
	"context"
	"fence/internal/xdpguard"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("fess-xdp", version)
		return nil
	}
	path := flag.String("config", "/etc/fess/xdp.json", "prefilter JSON configuration")
	check := flag.Bool("check", false, "validate configuration without loading BPF or attaching to a NIC")
	flag.Parse()
	cfg, err := xdpguard.ReadConfig(*path)
	if err != nil {
		return err
	}
	if *check {
		fmt.Println("XDP configuration valid")
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return xdpguard.Run(ctx, cfg)
}
