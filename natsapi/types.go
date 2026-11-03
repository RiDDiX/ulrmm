// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package api

// Wire format of the agent check-ins. The json tags are what the agent
// sends (msgpack keys) and the field order is fixed: types_test.go builds
// these with positional literals, and Disks/Services are written to the
// database as encoding/json output in this order.

type CheckInMsg struct {
	AgentID string `json:"agent_id"`
	Version string `json:"version"`
}

type PublicIPMsg struct {
	AgentID  string `json:"agent_id"`
	PublicIP string `json:"public_ip"`
}

type AgentInfoMsg struct {
	AgentID      string  `json:"agent_id"`
	Username     string  `json:"logged_in_username"`
	Hostname     string  `json:"hostname"`
	OS           string  `json:"operating_system"`
	Platform     string  `json:"plat"`
	TotalRAM     float64 `json:"total_ram"`
	BootTime     int64   `json:"boot_time"`
	RebootNeeded bool    `json:"needs_reboot"`
	GoArch       string  `json:"goarch"`
}

type Disk struct {
	Device  string `json:"device"`
	Fstype  string `json:"fstype"`
	Total   string `json:"total"`
	Used    string `json:"used"`
	Free    string `json:"free"`
	Percent int    `json:"percent"`
}

type DisksMsg struct {
	AgentID string `json:"agent_id"`
	Disks   []Disk `json:"disks"`
}

type Service struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	DisplayName string `json:"display_name"`
	BinPath     string `json:"binpath"`
	Description string `json:"description"`
	Username    string `json:"username"`
	PID         uint32 `json:"pid"`
	StartType   string `json:"start_type"`
	AutoDelay   bool   `json:"autodelay"`
}

type ServicesMsg struct {
	AgentID  string    `json:"agent_id"`
	Services []Service `json:"services"`
}

type WMIMsg struct {
	AgentID string      `json:"agent_id"`
	WMI     interface{} `json:"wmi"`
}

type PowerMsg struct {
	AgentID   string `json:"agent_id"`
	Kind      string `json:"kind"`
	Source    string `json:"source"`
	Initiator string `json:"initiator"`
}
