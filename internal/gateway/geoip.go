package gateway

import (
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"fence/internal/runtimebus"
	"github.com/oschwald/geoip2-golang"
)

var (
	geoMu     sync.RWMutex
	geoReader *geoip2.Reader
)

func reloadGeoIP(mmdbPath string) {
	mmdbPath = strings.TrimSpace(mmdbPath)
	geoMu.Lock()
	defer geoMu.Unlock()
	if geoReader != nil {
		_ = geoReader.Close()
		geoReader = nil
	}
	if mmdbPath == "" {
		return
	}
	r, err := geoip2.Open(mmdbPath)
	if err != nil {
		log.Printf("geoip: open %q: %v (country lookup disabled)", mmdbPath, err)
		return
	}
	geoReader = r
	log.Printf("geoip: loaded %s", mmdbPath)
}

func closeGeoIP() {
	geoMu.Lock()
	defer geoMu.Unlock()
	if geoReader != nil {
		_ = geoReader.Close()
		geoReader = nil
	}
}

func subscribeGeoIPUpdates(state *runtimebus.Client, mmdbPath string) {
	ctx := context.Background()
	sub := state.Subscribe(ctx, "geoip_mmdb_updated")
	go func() {
		defer sub.Close()
		for msg := range sub.Channel() {
			log.Printf("geoip mmdb event: %s", msg.Payload)
			reloadGeoIP(mmdbPath)
		}
	}()
}

func countryCodeForRequest(r *http.Request, clientIP string) string {
	if cc := strings.TrimSpace(r.Header.Get("CF-IPCountry")); cc != "" {
		u := strings.ToUpper(cc)
		if u != "" && u != "XX" && len(u) == 2 {
			return u
		}
	}
	geoMu.RLock()
	defer geoMu.RUnlock()
	if geoReader == nil || clientIP == "" {
		return ""
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return ""
	}
	rec, err := geoReader.Country(ip)
	if err != nil || rec.Country.IsoCode == "" {
		return ""
	}
	return strings.ToUpper(rec.Country.IsoCode)
}
