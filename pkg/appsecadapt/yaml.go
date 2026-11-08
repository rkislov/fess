package appsecadapt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go.yaml.in/yaml/v3"
	"io"
)

type Document struct {
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Rules       []Expression   `yaml:"rules"`
	Labels      map[string]any `yaml:"labels"`
}
type Report struct {
	Name       string            `json:"name"`
	Supported  bool              `json:"supported"`
	Reasons    []string          `json:"reasons"`
	SHA256     string            `json:"source_sha256"`
	Expression *Expression       `json:"expression,omitempty"`
	Semantics  map[string]string `json:"semantics"`
}

func Adapt(raw []byte) Report {
	sum := sha256.Sum256(raw)
	out := Report{SHA256: hex.EncodeToString(sum[:]), Reasons: []string{}, Semantics: map[string]string{"URI": "URL.Path (однократно декодированный путь)", "URI_FULL": "исходный path + query без схемы и Host", "HEADERS": "исходные значения HTTP-заголовков", "scope": "только статические HTTP AppSec-условия; не сценарии блокировки IP"}}
	fail := func(e error) Report { out.Reasons = append(out.Reasons, e.Error()); return out }
	if len(raw) == 0 || len(raw) > 1<<20 {
		return fail(fmt.Errorf("нужен один YAML-файл до 1 МиБ"))
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return fail(fmt.Errorf("неподдерживаемый YAML: %w", err))
	}
	out.Name = doc.Name
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fail(fmt.Errorf("принимается один YAML-документ"))
	}
	if doc.Name == "" || len(doc.Name) > 200 || len(doc.Rules) == 0 {
		return fail(fmt.Errorf("нужны name и непустые rules; scenarios/seclang напрямую не импортируются"))
	}
	expression := Expression{Or: doc.Rules}
	if _, err := Compile(expression); err != nil {
		return fail(err)
	}
	out.Supported = true
	out.Expression = &expression
	return out
}
