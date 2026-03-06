package registry

import "testing"

func TestGetOpenAIModels_IncludesGPT54Family(t *testing.T) {
	t.Parallel()

	models := GetOpenAIModels()
	want := []string{
		"gpt-5.4",
		"gpt-5.4-pro",
		"gpt-5.4-codex",
		"gpt-5.4-codex-spark",
	}

	for _, id := range want {
		found := false
		for _, model := range models {
			if model == nil {
				continue
			}
			if model.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected OpenAI static models to include %q", id)
		}
	}
}

func TestLookupStaticModelInfo_GPT54Family(t *testing.T) {
	t.Parallel()

	ids := []string{
		"gpt-5.4",
		"gpt-5.4-pro",
		"gpt-5.4-codex",
		"gpt-5.4-codex-spark",
	}

	for _, id := range ids {
		model := LookupStaticModelInfo(id)
		if model == nil {
			t.Fatalf("expected static lookup to find %q", id)
		}
		if model.ID != id {
			t.Fatalf("expected model id %q, got %q", id, model.ID)
		}
	}
}
