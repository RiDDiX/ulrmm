// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package api

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ugorji/go/codec"
)

type m = map[string]interface{}

// msgpack payloads, same keys an agent sends
func TestDecodeAgentMessages(t *testing.T) {
	disk := m{"device": "C:", "fstype": "NTFS", "total": "100 GB", "used": "40 GB", "free": "60 GB", "percent": 40}
	svc := m{"name": "Spooler", "status": "running", "display_name": "Print Spooler", "binpath": `C:\spoolsv.exe`,
		"description": "Queues print jobs", "username": "LocalSystem", "pid": uint32(812), "start_type": "Automatic", "autodelay": true}

	cases := []struct {
		in        m
		got, want interface{}
	}{
		{m{"agent_id": "a1", "version": "2.12.0"}, &CheckInMsg{}, &CheckInMsg{"a1", "2.12.0"}},
		{m{"agent_id": "a1", "public_ip": "203.0.113.7"}, &PublicIPMsg{}, &PublicIPMsg{"a1", "203.0.113.7"}},
		{m{"agent_id": "a1", "logged_in_username": "bob", "hostname": "pc1", "operating_system": "Windows 11",
			"plat": "windows", "total_ram": 15.5, "boot_time": int64(1700000000), "needs_reboot": true, "goarch": "amd64"},
			&AgentInfoMsg{}, &AgentInfoMsg{"a1", "bob", "pc1", "Windows 11", "windows", 15.5, 1700000000, true, "amd64"}},
		{m{"agent_id": "a1", "disks": []m{disk}}, &DisksMsg{},
			&DisksMsg{"a1", []Disk{{"C:", "NTFS", "100 GB", "40 GB", "60 GB", 40}}}},
		{m{"agent_id": "a1", "services": []m{svc}}, &ServicesMsg{},
			&ServicesMsg{"a1", []Service{{"Spooler", "running", "Print Spooler", `C:\spoolsv.exe`, "Queues print jobs", "LocalSystem", 812, "Automatic", true}}}},
		{m{"agent_id": "a1", "wmi": m{"cpu": []interface{}{"x"}}}, &WMIMsg{}, &WMIMsg{"a1", m{"cpu": []interface{}{"x"}}}},
	}
	for _, c := range cases {
		var b []byte
		if err := codec.NewEncoderBytes(&b, new(codec.MsgpackHandle)).Encode(c.in); err != nil {
			t.Fatal(err)
		}
		if err := msgDecoder(b).Decode(c.got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("got %+v, want %+v", c.got, c.want)
		}
	}

	// what ends up in the disks and services columns
	for _, c := range []struct {
		v    interface{}
		want string
	}{
		{cases[3].got.(*DisksMsg).Disks, `[{"device":"C:","fstype":"NTFS","total":"100 GB","used":"40 GB","free":"60 GB","percent":40}]`},
		{cases[4].got.(*ServicesMsg).Services, `[{"name":"Spooler","status":"running","display_name":"Print Spooler","binpath":"C:\\spoolsv.exe","description":"Queues print jobs","username":"LocalSystem","pid":812,"start_type":"Automatic","autodelay":true}]`},
	} {
		b, _ := json.Marshal(c.v)
		if string(b) != c.want {
			t.Errorf("json %s, want %s", b, c.want)
		}
	}
}

func TestLoggedInUser(t *testing.T) {
	for in, want := range map[string]string{"": "None", "  ": "None", "None": "None", "bob": "bob"} {
		if got := loggedInUser(in); got != want {
			t.Errorf("loggedInUser(%q) = %q, want %q", in, got, want)
		}
	}
}
