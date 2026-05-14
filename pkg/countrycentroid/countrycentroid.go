package countrycentroid

import (
	_ "embed"
	"encoding/csv"
	"strconv"
	"strings"
)

//go:embed centroids.csv
var centroidsCSV string

var byCode map[string][2]float64

func init() {
	byCode = make(map[string][2]float64)
	r := csv.NewReader(strings.NewReader(centroidsCSV))
	r.TrimLeadingSpace = true
	rows, err := r.ReadAll()
	if err != nil {
		panic("countrycentroid: parse centroids.csv: " + err.Error())
	}
	for _, row := range rows {
		if len(row) < 3 {
			continue
		}
		code := strings.ToUpper(strings.TrimSpace(row[0]))
		lat, e1 := strconv.ParseFloat(strings.TrimSpace(row[1]), 64)
		lon, e2 := strconv.ParseFloat(strings.TrimSpace(row[2]), 64)
		if e1 != nil || e2 != nil {
			continue
		}
		byCode[code] = [2]float64{lat, lon}
	}
}

// LatLon returns approximate country centroid (degrees). ok is false if unknown ISO code.
func LatLon(iso2 string) (lat, lon float64, ok bool) {
	code := strings.ToUpper(strings.TrimSpace(iso2))
	if code == "" {
		return 0, 0, false
	}
	ll, ok := byCode[code]
	if !ok {
		return 0, 0, false
	}
	return ll[0], ll[1], true
}
