package model

import "time"

type Level string

const (
	LevelInfo     Level = "info"
	LevelLow      Level = "low"
	LevelMedium   Level = "medium"
	LevelHigh     Level = "high"
	LevelCritical Level = "critical"
)

type Op string

const (
	OpCreate Op = "create"
	OpWrite  Op = "write"
	OpRename Op = "rename"
	OpRemove Op = "remove"
	OpChmod  Op = "chmod"
	OpScan   Op = "scan"
)

type FileEvent struct {
	Op    Op
	Path  string
	IsDir bool
	Time  time.Time
}

type Finding struct {
	RuleID  string
	Level   Level
	Message string
	Path    string
	Time    time.Time
}

type ProcessEvent struct {
	Pid        int32
	Name       string
	Exe        string
	Cwd        string
	ParentPid  int32
	ParentName string
	Time       time.Time
}
