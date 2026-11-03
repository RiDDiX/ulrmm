// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package api

import (
	"strings"
	"testing"

	"github.com/lib/pq"
)

func TestCleanAndColumns(t *testing.T) {
	if got := clean("ok ä"); got != "ok ä" {
		t.Errorf("clean changed a clean value: %q", got)
	}
	if got := clean("a\x00b\xffc"); got != "ab�c" {
		t.Errorf("clean = %q", got)
	}
	if got := col(strings.Repeat("é", 300)); len([]rune(got)) != 255 {
		t.Errorf("col kept %d runes", len([]rune(got)))
	}
	w := cleanAny(map[string]interface{}{"k\x00": []interface{}{"v\x00", 1}}).(map[string]interface{})
	if w["k"].([]interface{})[0] != "v" {
		t.Errorf("cleanAny = %#v", w)
	}
}

func TestDSNQuoting(t *testing.T) {
	c := &config{Host: "localhost", Port: 5432, User: "u", Pass: `p w'\x sslmode=require`, DBName: "ulrmm", SSLMode: "disable"}
	conn, err := pq.NewConnector(c.dsn())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn
	if !strings.Contains(c.dsn(), `password='p w\'\\x sslmode=require'`) {
		t.Errorf("dsn = %s", c.dsn())
	}
}
