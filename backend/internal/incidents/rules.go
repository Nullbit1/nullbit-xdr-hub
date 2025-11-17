package incidents

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type RuleSet struct {
	Rules []RuleConfig `yaml:"rules"`
}

type RuleConfig struct {
	ID          string      `yaml:"id"`
	Title       string      `yaml:"title"`
	Description string      `yaml:"description"`
	Severity    string      `yaml:"severity"`
	Window      time.Duration `yaml:"window"`
	Tags        []string    `yaml:"tags"`
	Steps       []RuleStep  `yaml:"steps"`
}

type RuleStep struct {
	Name  string    `yaml:"name"`
	Match StepMatch `yaml:"match"`
}

type StepMatch struct {
	Source        string            `yaml:"source"`
	Kind          string            `yaml:"kind"`
	TagsAny       []string          `yaml:"tags_any"`
	FieldEquals   map[string]string `yaml:"field_equals"`
	FieldContains map[string]string `yaml:"field_contains"`
}

func LoadRules(path string) ([]RuleConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, err
	}
	for i := range rs.Rules {
		if rs.Rules[i].Window == 0 {
			rs.Rules[i].Window = 5 * time.Minute
		}
	}
	return rs.Rules, nil
}
