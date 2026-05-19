package main

import (
	"encoding/json"
	"testing"
)

func TestExtractAIChoiceTextReasoningField(t *testing.T) {
	raw := `{"choices":[{"message":{"role":"assistant","content":null,"reasoning":"Краткий анализ: трафик в норме."}}]}`
	var parsed openAIChatResp
	if err := jsonUnmarshalTest(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	got := extractAIChoiceText(parsed.Choices[0])
	if got != "Краткий анализ: трафик в норме." {
		t.Fatalf("got %q", got)
	}
}

func TestExtractAIChoiceTextContentString(t *testing.T) {
	raw := `{"choices":[{"message":{"role":"assistant","content":"hello"}}]}`
	var parsed openAIChatResp
	if err := jsonUnmarshalTest(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if got := extractAIChoiceText(parsed.Choices[0]); got != "hello" {
		t.Fatalf("got %q", got)
	}
}

func jsonUnmarshalTest(raw string, v any) error {
	return json.Unmarshal([]byte(raw), v)
}
