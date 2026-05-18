package main

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
	"github.com/redis/go-redis/v9"
)

var (
	asnMu     sync.RWMutex
	asnReader *geoip2.Reader
)

func reloadGeoASN(mmdbPath string) {
	mmdbPath = strings.TrimSpace(mmdbPath)
	asnMu.Lock()
	defer asnMu.Unlock()
	if asnReader != nil {
		_ = asnReader.Close()
		asnReader = nil
	}
	if mmdbPath == "" {
		return
	}
	r, err := geoip2.Open(mmdbPath)
	if err != nil {
		log.Printf("geoip asn: open %q: %v (ASN lookup disabled)", mmdbPath, err)
		return
	}
	asnReader = r
	log.Printf("geoip asn: loaded %s", mmdbPath)
}

func subscribeGeoASNUpdates(rdb *redis.Client, mmdbPath string) {
	ctx := context.Background()
	sub := rdb.Subscribe(ctx, "geoip_asn_mmdb_updated", "bot_protection_updated")
	defer sub.Close()
	for msg := range sub.Channel() {
		log.Printf("geoip asn event: %s", msg.Payload)
		reloadGeoASN(mmdbPath)
	}
}

func asnForIP(clientIP string) (uint, string, bool) {
	asnMu.RLock()
	defer asnMu.RUnlock()
	if asnReader == nil || clientIP == "" {
		return 0, "", false
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return 0, "", false
	}
	rec, err := asnReader.ASN(ip)
	if err != nil || rec.AutonomousSystemNumber == 0 {
		return 0, "", false
	}
	return uint(rec.AutonomousSystemNumber), rec.AutonomousSystemOrganization, true
}
