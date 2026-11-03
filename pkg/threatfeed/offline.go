package threatfeed

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strings"
)

const OfflineFormat = "security-feed-offline-v1"

type OfflineFile struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Count  int    `json:"count"`
}
type OfflineManifest struct {
	Format string                 `json:"format"`
	Files  map[string]OfflineFile `json:"files"`
}
type OfflineBundle struct {
	IPs, Hashes, Domains, URLs []string
	ClamAV                     map[string]*zip.File
	Manifest                   OfflineManifest
}

// ParseOffline verifies every data file before any database or CVD is replaced.
// Entries are never extracted using names supplied by the archive.
func ParseOffline(r io.ReaderAt, size int64) (OfflineBundle, error) {
	var out OfflineBundle
	z, err := zip.NewReader(r, size)
	if err != nil {
		return out, fmt.Errorf("некорректный ZIP")
	}
	files := map[string]*zip.File{}
	var total uint64
	for _, f := range z.File {
		if _, ok := files[f.Name]; ok {
			return out, fmt.Errorf("повтор файла в ZIP")
		}
		if len(z.File) > 16 || f.UncompressedSize64 > 400<<20 || total+f.UncompressedSize64 > 640<<20 {
			return out, fmt.Errorf("архив превышает лимит")
		}
		total += f.UncompressedSize64
		files[f.Name] = f
	}
	read := func(name string, limit int64) ([]byte, error) {
		f := files[name]
		if f == nil {
			return nil, fmt.Errorf("нет %s", name)
		}
		rc, e := f.Open()
		if e != nil {
			return nil, e
		}
		defer rc.Close()
		b, e := io.ReadAll(io.LimitReader(rc, limit+1))
		if e != nil || int64(len(b)) > limit {
			return nil, fmt.Errorf("некорректный размер %s", name)
		}
		return b, nil
	}
	raw, err := read("manifest.json", 64<<10)
	if err != nil {
		return out, err
	}
	if json.Unmarshal(raw, &out.Manifest) != nil || out.Manifest.Format != OfflineFormat {
		return out, fmt.Errorf("неподдерживаемый формат выгрузки")
	}
	out.ClamAV = map[string]*zip.File{}
	allowed := map[string]bool{"ips.txt": true, "hashes.txt": true, "domains.txt": true, "urls.txt": true, "clamav/main.cvd": true, "clamav/daily.cvd": true, "clamav/bytecode.cvd": true}
	for _, name := range []string{"ips.txt", "hashes.txt", "domains.txt", "urls.txt"} {
		if _, ok := out.Manifest.Files[name]; !ok {
			return out, fmt.Errorf("нет %s в manifest", name)
		}
	}
	for name, meta := range out.Manifest.Files {
		if !allowed[name] {
			return out, fmt.Errorf("неподдерживаемый файл данных")
		}
		f := files[name]
		if f == nil || meta.Bytes < 0 || uint64(meta.Bytes) != f.UncompressedSize64 {
			return out, fmt.Errorf("неверный размер %s", name)
		}
		rc, e := f.Open()
		if e != nil {
			return out, e
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(rc, meta.Bytes+1))
		rc.Close()
		if e != nil || n != meta.Bytes || hex.EncodeToString(h.Sum(nil)) != meta.SHA256 {
			return out, fmt.Errorf("контрольная сумма %s не совпала", name)
		}
		if strings.HasPrefix(name, "clamav/") {
			out.ClamAV[strings.TrimPrefix(name, "clamav/")] = f
			continue
		}
		b, e := read(name, 64<<20)
		if e != nil {
			return out, e
		}
		scanner := bufio.NewScanner(strings.NewReader(string(b)))
		scanner.Buffer(make([]byte, 4096), 1<<20)
		count := 0
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			count++
			switch name {
			case "ips.txt":
				if a, e := netip.ParseAddr(line); e == nil {
					out.IPs = append(out.IPs, a.Unmap().String())
				} else if p, e := netip.ParsePrefix(line); e == nil {
					out.IPs = append(out.IPs, p.Masked().String())
				} else {
					return out, fmt.Errorf("некорректный IP/CIDR")
				}
			case "hashes.txt":
				h := NormalizeFileHash(line)
				if h == "" {
					return out, fmt.Errorf("некорректный хэш")
				}
				out.Hashes = append(out.Hashes, h)
			case "domains.txt":
				if strings.ContainsAny(line, " /@:?#\t\r\n") {
					return out, fmt.Errorf("некорректный домен")
				}
				out.Domains = append(out.Domains, line)
			case "urls.txt":
				u, e := url.Parse(line)
				if e != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || strings.ContainsAny(line, " \t\r\n") {
					return out, fmt.Errorf("некорректный URL")
				}
				out.URLs = append(out.URLs, line)
			}
		}
		if scanner.Err() != nil || count != meta.Count {
			return out, fmt.Errorf("число записей %s не совпало", name)
		}
	}
	if len(out.ClamAV) != 0 && len(out.ClamAV) != 3 {
		return out, fmt.Errorf("нужны все три базы ClamAV")
	}
	out.IPs = UniqueIndicatorsPlain(out.IPs)
	out.Hashes = UniqueFileHashes(out.Hashes)
	if len(out.IPs)+len(out.Hashes)+len(out.Domains)+len(out.URLs) == 0 {
		return out, fmt.Errorf("пустой архив IOC")
	}
	return out, nil
}
func UniqueIndicatorsPlain(v []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range v {
		if !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
	}
	return out
}
