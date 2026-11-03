// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package api

import (
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
	"github.com/ugorji/go/codec"
)

func TestCheckInSubjects(t *testing.T) {
	if len(checkinSubjects) != 2 || checkinSubjects[0] != "*" || checkinSubjects[1] != "*.checkin" {
		t.Fatalf("subscribed to %v", checkinSubjects)
	}
	var b []byte
	if err := codec.NewEncoderBytes(&b, new(codec.MsgpackHandle)).Encode(m{"agent_id": "a1", "version": "2.25.10.2026"}); err != nil {
		t.Fatal(err)
	}
	w := &worker{log: logrus.New(), mismatch: throttle{every: time.Minute}}
	for subject, ok := range map[string]bool{"a1": true, "a1.checkin": true, "a2": false, "a2.checkin": false, "a1.cmdoutput": false} {
		p := &CheckInMsg{}
		if got := w.decode(&nats.Msg{Subject: subject, Data: b}, &p.AgentID, p); got != ok {
			t.Errorf("decode on %q = %v, want %v", subject, got, ok)
		}
	}
}

func TestPowerUpdate(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, kind := range []string{"", "reboot", "Shutdown", "hibernate"} {
		if _, _, ok := powerUpdate(&PowerMsg{AgentID: "a1", Kind: kind}, now); ok {
			t.Errorf("kind %q accepted", kind)
		}
	}
	q, args, ok := powerUpdate(&PowerMsg{AgentID: "a1", Kind: "cancel", Initiator: "bob"}, now)
	if !ok || args[0] != "" || args[1] != now || args[2] != "bob" || args[3] != "a1" || !strings.Contains(q, "power_event=$1, power_event_at=$2, power_event_by=CASE WHEN $5 = 'rmm' AND $3 = ''") {
		t.Errorf("cancel: %q %v", q, args)
	}
	long := strings.Repeat("é", 300) + "\x00"
	for _, kind := range []string{"shutdown", "restart", "shutdown_or_restart", "sleep"} {
		_, args, ok := powerUpdate(&PowerMsg{AgentID: "a1", Kind: kind, Source: "os", Initiator: long}, now)
		if !ok || args[0] != kind || args[1] != now || args[3] != "a1" {
			t.Fatalf("%s: %v", kind, args)
		}
		if n := len([]rune(args[2].(string))); n != maxInitiator {
			t.Errorf("initiator kept %d runes", n)
		}
	}
	if _, args, _ := powerUpdate(&PowerMsg{AgentID: "a1", Kind: "restart", Source: "rmm"}, now); args[4] != "rmm" {
		t.Errorf("source not passed: %v", args)
	}
	if q, _, _ := powerUpdate(&PowerMsg{AgentID: "a1", Kind: "restart"}, now); strings.Contains(q, "last_seen") {
		t.Errorf("touches last_seen: %q", q)
	}
	if !modes[modePower] || modePower != "agent-power" {
		t.Error("agent-power is not a check-in mode")
	}

	var b []byte
	in := m{"agent_id": "a1", "kind": "sleep", "source": "os", "initiator": "lid"}
	if err := codec.NewEncoderBytes(&b, new(codec.MsgpackHandle)).Encode(in); err != nil {
		t.Fatal(err)
	}
	p := &PowerMsg{}
	w := &worker{log: logrus.New(), mismatch: throttle{every: time.Minute}}
	if !w.decode(&nats.Msg{Subject: "a1.checkin", Data: b}, &p.AgentID, p) || *p != (PowerMsg{"a1", "sleep", "os", "lid"}) {
		t.Errorf("decoded %+v", p)
	}
}
