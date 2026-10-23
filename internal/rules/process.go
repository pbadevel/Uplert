package rules

import (
	"github.com/pbadevel/Uplert/internal/model"
)

type ProcessRule interface {
	ID() string
	Evaluate(ev model.ProcessEvent) []model.Finding
}

type ProcessRegistry struct {
	rules []ProcessRule
}

func NewProcessRegistry(ruleList ...ProcessRule) *ProcessRegistry {
	return &ProcessRegistry{rules: ruleList}
}

func (r *ProcessRegistry) Evaluate(ev model.ProcessEvent) []model.Finding {
	var findings []model.Finding
	for _, rule := range r.rules {
		findings = append(findings, rule.Evaluate(ev)...)
	}
	return findings
}
