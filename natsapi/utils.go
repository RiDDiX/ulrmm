// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package api

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ugorji/go/codec"
)

const defaultConfigPath = "/rmm/api/ulrmm/nats-api.conf"

// config is the file written by "manage.py create_natsapi_conf".
type config struct {
	Key     string `json:"key"`
	NatsURL string `json:"natsurl"`
	User    string `json:"user"`
	Pass    string `json:"pass"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	DBName  string `json:"dbname"`
	SSLMode string `json:"sslmode"`
}

func loadConfig(path string) (*config, error) {
	if path == "" {
		path = defaultConfigPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &config{}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// pqQuote quotes a value for a libpq key/value connection string.
func pqQuote(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `'`, `\'`)
	return "'" + v + "'"
}

func (c *config) dsn() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		pqQuote(c.Host), c.Port, pqQuote(c.User), pqQuote(c.Pass), pqQuote(c.DBName), pqQuote(c.SSLMode))
}

var mpHandle = func() *codec.MsgpackHandle {
	h := &codec.MsgpackHandle{}
	h.RawToString = true
	h.MapType = reflect.TypeOf(map[string]interface{}(nil))
	return h
}()

func msgDecoder(b []byte) *codec.Decoder {
	return codec.NewDecoderBytes(b, mpHandle)
}

// loggedInUser maps an empty or blank username to "None", which is what
// Django treats as "nobody logged in".
func loggedInUser(s string) string {
	if strings.TrimSpace(s) == "" {
		return "None"
	}
	return s
}

// clean drops NUL bytes and replaces invalid UTF-8; Postgres refuses both
// in text and jsonb. Clean input comes back unchanged.
func clean(s string) string {
	if strings.IndexByte(s, 0) < 0 && utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "�")
}

// col cleans a value for a varchar(255) column and cuts it to 255 characters.
func col(s string) string {
	s = clean(s)
	if utf8.RuneCountInString(s) <= 255 {
		return s
	}
	return string([]rune(s)[:255])
}

func cleanAny(v interface{}) interface{} {
	switch t := v.(type) {
	case string:
		return clean(t)
	case []interface{}:
		for i := range t {
			t[i] = cleanAny(t[i])
		}
		return t
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, x := range t {
			out[clean(k)] = cleanAny(x)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[interface{}]interface{}, len(t))
		for k, x := range t {
			out[cleanAny(k)] = cleanAny(x)
		}
		return out
	}
	return v
}

func (d *Disk) clean() {
	for _, p := range []*string{&d.Device, &d.Fstype, &d.Total, &d.Used, &d.Free} {
		*p = clean(*p)
	}
}

func (s *Service) clean() {
	for _, p := range []*string{&s.Name, &s.Status, &s.DisplayName, &s.BinPath, &s.Description, &s.Username, &s.StartType} {
		*p = clean(*p)
	}
}

// throttle lets one log line through per interval and counts the rest.
type throttle struct {
	mu         sync.Mutex
	every      time.Duration
	last       time.Time
	suppressed int
}

// allow reports whether to log now and how many lines were held back since
// the last one.
func (t *throttle) allow() (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if now := time.Now(); now.Sub(t.last) >= t.every {
		n := t.suppressed
		t.last, t.suppressed = now, 0
		return true, n
	}
	t.suppressed++
	return false, 0
}
