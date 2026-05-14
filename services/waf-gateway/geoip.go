package main

import (
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

var geoReader *geoip2.Reader

func initGeoIP(mmdbPath string) {
	if strings.TrimSpace(mmdbPath) == "" {
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
	if geoReader != nil {
		_ = geoReader.Close()
		geoReader = nil
	}
}

func countryCodeForRequest(r *http.Request, clientIP string) string {
	if cc := strings.TrimSpace(r.Header.Get("CF-IPCountry")); cc != "" {
		u := strings.ToUpper(cc)
		if u != "" && u != "XX" && len(u) == 2 {
			return u
		}
	}
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
