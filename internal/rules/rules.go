package rules

import (
	"github.com/pbadevel/Uplert/internal/model"
)

type Rule interface {
	ID() string
	Evaluate(ev model.FileEvent) []model.Finding
}

type Registry struct {
	rules []Rule
}

func NewRegistry(ruleList ...Rule) *Registry {
	return &Registry{rules: ruleList}
}

func (r *Registry) Evaluate(ev model.FileEvent) []model.Finding {
	var findings []model.Finding
	for _, rule := range r.rules {
		findings = append(findings, rule.Evaluate(ev)...)
	}
	return findings
}
