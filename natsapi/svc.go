// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package api

import (
	"context"
	"encoding/json"
	"math"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
)

// Reply subjects the agent uses to say what kind of check-in it sends.
const (
	modeHello     = "agent-hello"
	modePublicIP  = "agent-publicip"
	modeAgentInfo = "agent-agentinfo"
	modeDisks     = "agent-disks"
	modeWinSvc    = "agent-winsvc"
	modeWMI       = "agent-wmi"
	modePower     = "agent-power"
)

// Agents from 2.25.10.2026 on check in on <agent_id>.checkin, older ones on
// <agent_id>, which is also the subject their commands arrive on.
var checkinSubjects = []string{"*", "*.checkin"}

// subjectAgent is the agent id a check-in subject belongs to.
func subjectAgent(subject string) string {
	return strings.TrimSuffix(subject, ".checkin")
}

var modes = map[string]bool{
	modeHello: true, modePublicIP: true, modeAgentInfo: true,
	modeDisks: true, modeWinSvc: true, modeWMI: true, modePower: true,
}

// what an agent may announce before it goes away; cancel clears it
var powerKinds = map[string]bool{
	"shutdown": true, "restart": true, "shutdown_or_restart": true, "sleep": true,
}

const maxInitiator = 255

const (
	workers    = 16
	queueSize  = 4096
	pendingMsg = 65536
	pendingMem = 64 << 20

	maxDisks    = 512
	maxServices = 4096
	maxDisksB   = 256 << 10
	maxSvcB     = 4 << 20
	maxWMIB     = 8 << 20
)

type worker struct {
	log      *logrus.Logger
	db       *sqlx.DB
	mismatch throttle
	tooBig   throttle
}

func connectDB(log *logrus.Logger, c *config, stop <-chan struct{}) *sqlx.DB {
	wait := time.Second
	deadline := time.Now().Add(5 * time.Minute)
	for {
		db, err := sqlx.Connect("postgres", c.dsn())
		if err == nil {
			db.SetMaxOpenConns(20)
			db.SetMaxIdleConns(20)
			db.SetConnMaxIdleTime(5 * time.Minute)
			return db
		}
		if time.Now().After(deadline) {
			log.Fatalln("database:", err)
		}
		log.Errorf("database not reachable, retrying in %s: %v", wait, err)
		select {
		case <-stop:
			log.Fatalln("stopped while waiting for the database")
		case <-time.After(wait):
		}
		if wait *= 2; wait > 30*time.Second {
			wait = 30 * time.Second
		}
	}
}

// Svc runs the check-in writer until SIGINT/SIGTERM.
func Svc(log *logrus.Logger, cfg string) {
	log.Debugln("Starting Svc()")
	c, err := loadConfig(cfg)
	if err != nil {
		log.Fatalln("config:", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	w := &worker{log: log, mismatch: throttle{every: time.Minute}, tooBig: throttle{every: time.Minute}}
	w.db = connectDB(log, c, ctx.Done())
	defer w.db.Close()

	closed := make(chan struct{})
	nc, err := nats.Connect(c.NatsURL,
		nats.Name("ulrmm-nats-api"),
		nats.UserInfo("ulrmm", c.Key),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.RetryOnFailedConnect(true),
		nats.IgnoreAuthErrorAbort(),
		nats.ReconnectBufSize(-1),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			log.Debugf("nats disconnected: %v %+v", err, nc.Stats())
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			log.Debugf("nats reconnected to %s %+v", nc.ConnectedUrl(), nc.Stats())
		}),
		nats.ErrorHandler(func(_ *nats.Conn, sub *nats.Subscription, err error) {
			subj := ""
			if sub != nil {
				subj = sub.Subject
			}
			log.Errorf("nats error on %q: %v", subj, err)
		}),
		nats.ClosedHandler(func(*nats.Conn) { close(closed) }),
	)
	if err != nil {
		log.Fatalln("nats:", err)
	}

	queue := make(chan *nats.Msg, queueSize)
	var dropped atomic.Int64
	enqueue := func(m *nats.Msg) {
		// Django's commands to agents arrive here too (_INBOX replies);
		// only the check-in kinds are of interest.
		if !modes[m.Reply] {
			return
		}
		// one subscription delivers in order; the shared queue would not,
		// and a cancel must not overtake the shutdown it follows
		if m.Reply == modePower {
			w.handle(m)
			return
		}
		select {
		case queue <- m:
		default:
			dropped.Add(1)
		}
	}
	subs := make([]*nats.Subscription, 0, len(checkinSubjects))
	for _, subject := range checkinSubjects {
		sub, err := nc.Subscribe(subject, enqueue)
		if err != nil {
			log.Fatalln("nats subscribe:", err)
		}
		if err := sub.SetPendingLimits(pendingMsg, pendingMem); err != nil {
			log.Fatalln("nats pending limits:", err)
		}
		subs = append(subs, sub)
	}
	_ = nc.Flush()
	if err := nc.LastError(); err != nil {
		log.Fatalln("nats:", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case m := <-queue:
					w.handle(m)
				case <-stop:
					for {
						select {
						case m := <-queue:
							w.handle(m)
						default:
							return
						}
					}
				}
			}
		}()
	}

	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	var lastNatsDrop int
	for {
		select {
		case <-tick.C:
			if n := dropped.Swap(0); n > 0 {
				log.Errorf("queue full, dropped %d check-ins in the last minute", n)
			}
			n := 0
			for _, sub := range subs {
				if d, err := sub.Dropped(); err == nil {
					n += d
				}
			}
			if n != lastNatsDrop {
				log.Errorf("nats client dropped %d check-ins in total (slow consumer)", n)
				lastNatsDrop = n
			}
		case <-ctx.Done():
			log.Infoln("shutting down")
			if err := nc.Drain(); err != nil {
				nc.Close()
			}
			select {
			case <-closed:
			case <-time.After(10 * time.Second):
				nc.Close()
			}
			close(stop)
			wg.Wait()
			return
		}
	}
}

func (w *worker) exec(query string, args ...interface{}) {
	if _, err := w.db.Exec(query, args...); err != nil {
		w.log.Errorln(err)
	}
}

func (w *worker) marshal(what, id string, v interface{}, max int) ([]byte, bool) {
	b, err := json.Marshal(v)
	if err != nil {
		w.log.Errorln(err)
		return nil, false
	}
	if len(b) > max {
		if ok, n := w.tooBig.allow(); ok {
			w.log.Errorf("%s of %q is %d bytes (limit %d), not stored (%d similar lines suppressed)", what, id, len(b), max, n)
		}
		return nil, false
	}
	return b, true
}

// decode reads the payload into v and checks that the agent published on
// its own subject.
func (w *worker) decode(m *nats.Msg, id *string, v interface{}) bool {
	if err := msgDecoder(m.Data).Decode(v); err != nil {
		return false
	}
	if *id != subjectAgent(m.Subject) {
		if ok, n := w.mismatch.allow(); ok {
			w.log.Errorf("agent_id mismatch: subject=%q agent_id=%q (%d similar lines suppressed)", m.Subject, *id, n)
		}
		return false
	}
	return true
}

func (w *worker) handle(m *nats.Msg) {
	switch m.Reply {
	case modeHello:
		p := &CheckInMsg{}
		if !w.decode(m, &p.AgentID, p) {
			return
		}
		w.log.Debugf("Hello %+v", p)
		// awake again a while after a sleep: an agent without power messages
		// never sends the cancel
		w.exec("UPDATE agents_agent SET last_seen=$1, version=$2, power_event=CASE WHEN power_event='sleep' AND power_event_at < $1::timestamptz - interval '60 seconds' THEN '' ELSE power_event END WHERE agents_agent.agent_id=$3",
			time.Now().UTC(), col(p.Version), p.AgentID)

	case modePublicIP:
		p := &PublicIPMsg{}
		if !w.decode(m, &p.AgentID, p) {
			return
		}
		w.log.Debugf("Public IP %+v", p)
		w.exec("UPDATE agents_agent SET public_ip=$1 WHERE agents_agent.agent_id=$2", col(p.PublicIP), p.AgentID)

	case modeAgentInfo:
		p := &AgentInfoMsg{}
		if !w.decode(m, &p.AgentID, p) {
			return
		}
		w.log.Debugf("Info %+v", p)
		user := col(loggedInUser(p.Username))
		// booted after a shutdown or restart was announced: it is back
		w.exec("UPDATE agents_agent SET hostname=$1, operating_system=$2, plat=$3, total_ram=$4, boot_time=$5, needs_reboot=$6, logged_in_username=$7, goarch=$8, power_event=CASE WHEN power_event IN ('shutdown', 'restart', 'shutdown_or_restart') AND to_timestamp($5) > power_event_at THEN '' ELSE power_event END WHERE agents_agent.agent_id=$9",
			col(p.Hostname), col(p.OS), col(p.Platform), int64(math.Round(p.TotalRAM)), p.BootTime, p.RebootNeeded, user, col(p.GoArch), p.AgentID)
		if user != "None" {
			w.log.Debugln("Updating last logged in user:", user)
			w.exec("UPDATE agents_agent SET last_logged_in_user=$1 WHERE agents_agent.agent_id=$2", user, p.AgentID)
		}

	case modeDisks:
		p := &DisksMsg{}
		if !w.decode(m, &p.AgentID, p) {
			return
		}
		w.log.Debugf("Disks %+v", p)
		if len(p.Disks) > maxDisks {
			p.Disks = p.Disks[:maxDisks]
		}
		for i := range p.Disks {
			p.Disks[i].clean()
		}
		if b, ok := w.marshal("disks", p.AgentID, p.Disks, maxDisksB); ok {
			w.exec("UPDATE agents_agent SET disks=$1 WHERE agents_agent.agent_id=$2", b, p.AgentID)
		}

	case modeWinSvc:
		p := &ServicesMsg{}
		if !w.decode(m, &p.AgentID, p) {
			return
		}
		w.log.Debugf("WinSvc %+v", p)
		if len(p.Services) > maxServices {
			p.Services = p.Services[:maxServices]
		}
		for i := range p.Services {
			p.Services[i].clean()
		}
		if b, ok := w.marshal("services", p.AgentID, p.Services, maxSvcB); ok {
			w.exec("UPDATE agents_agent SET services=$1 WHERE agents_agent.agent_id=$2", b, p.AgentID)
		}

	case modeWMI:
		p := &WMIMsg{}
		if !w.decode(m, &p.AgentID, p) {
			return
		}
		w.log.Debugf("WMI %+v", p)
		if b, ok := w.marshal("wmi", p.AgentID, cleanAny(p.WMI), maxWMIB); ok {
			w.exec("UPDATE agents_agent SET wmi_detail=$1 WHERE agents_agent.agent_id=$2", b, p.AgentID)
		}

	case modePower:
		p := &PowerMsg{}
		if !w.decode(m, &p.AgentID, p) {
			return
		}
		w.log.Debugf("Power %+v", p)
		q, args, ok := powerUpdate(p, time.Now().UTC())
		if !ok {
			w.log.Debugf("Power: unknown kind %q from %s", p.Kind, p.AgentID)
			return
		}
		w.exec(q, args...)
	}
}

// powerUpdate is the statement for a power announcement. Server time is
// stored, the agent sends none; a cancel stores an empty kind.
func powerUpdate(p *PowerMsg, now time.Time) (string, []interface{}, bool) {
	kind := p.Kind
	if kind == "cancel" {
		kind = ""
	} else if !powerKinds[kind] {
		return "", nil, false
	}
	by := []rune(clean(p.Initiator))
	if len(by) > maxInitiator {
		by = by[:maxInitiator]
	}
	// a server command names its user itself (Django), the agent sends ""
	return "UPDATE agents_agent SET power_event=$1, power_event_at=$2, power_event_by=CASE WHEN $5 = 'rmm' AND $3 = '' THEN power_event_by ELSE $3 END WHERE agents_agent.agent_id=$4",
		[]interface{}{kind, now, string(by), p.AgentID, p.Source}, true
}
