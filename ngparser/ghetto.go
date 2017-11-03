package ngparser

import (
	"bufio"
	"io"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type StatType uint8

const ( // StatTypes
	IPs StatType = iota
	StatusCodes
	Pages
	Hits
	UserAgents
	Extensions

	maxType
)
const (
	timeFmt = `2/Jan/2006:15:04:05 -0700`
)

var re = regexp.MustCompile(`(.+?)\s[^[]+\[([^]]+)\]\s"(\w+) (.+?)\sHTTP/(\d\.\d)"\s+\d+\s+(\d+)\s+"([^"]+)"\s+"([^"]+)"`)

// $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for";
type Record struct {
	IP        string
	TS        time.Time
	Method    string
	Filename  string
	Status    string
	Referer   string
	UserAgent string
}

type Stat struct {
	Name  string
	Value uint64
}

type stats map[string]uint64

func (s stats) ToSlice(min uint64) []Stat {
	out := make([]Stat, 0, len(s))
	for k, v := range s {
		if min > 0 && v < min {
			continue
		}
		out = append(out, Stat{k, v})
	}
	return out[:len(out):len(out)] // trim the slice to release the unused memory
}

type Parser struct {
	mux   sync.RWMutex
	data  [maxType]stats
	count uint64
	ipv6  uint64
}

func New() *Parser {
	var p Parser
	for i := range p.data {
		p.data[i] = stats{}
	}
	return &p
}

func (p *Parser) Parse(r io.Reader, fn func(r *Record)) {
	// p.mux.Lock()
	// defer p.mux.Unlock()
	var (
		sc  = bufio.NewScanner(r)
		in  = make(chan string, runtime.NumCPU())
		out = make(chan *Record, runtime.NumCPU())
		wg  sync.WaitGroup
	)

	for i := 0; i < cap(in); i++ {
		wg.Add(1)
		go p.parseLine(&wg, in, out)
	}

	go func() {
		for sc.Scan() {
			in <- sc.Text()
		}
		close(in)
		wg.Wait()
		close(out)
	}()

	for r := range out {
		if fn != nil {
			fn(r)
		}

		cleanPath := r.Filename
		if idx := strings.IndexByte(cleanPath, '?'); idx != -1 {
			cleanPath = cleanPath[:idx]
		}

		p.mux.Lock()
		ipCnt := p.data[IPs][r.IP]
		if strings.IndexByte(r.IP, ':') > -1 && ipCnt == 0 {
			p.ipv6++
		}
		p.data[IPs][r.IP] = ipCnt + 1
		p.data[StatusCodes][r.Status]++
		p.data[Pages][cleanPath]++
		p.data[Hits][r.Filename]++
		p.data[UserAgents][r.UserAgent]++ // probably should parse the agent and store something like Chrome-XX, IE11, Edge, etc.
		p.data[Extensions][filepath.Ext(cleanPath)]++
		p.count++
		p.mux.Unlock()
	}
}

func (p *Parser) Stats(t StatType, filterMin uint64) (out []Stat) {
	p.mux.RLock()
	out = p.data[t].ToSlice(filterMin)
	p.mux.RUnlock()

	// sorting outside the lock
	sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })

	return
}

func (p *Parser) Count() (l uint64) {
	p.mux.RLock()
	l = p.count
	p.mux.RUnlock()
	return
}

func (p *Parser) IPsCount() (v4, v6 uint64) {
	p.mux.RLock()
	total := uint64(len(p.data[IPs]))
	ipv6 := p.ipv6
	p.mux.RUnlock()
	return total - ipv6, ipv6
}

func (p *Parser) parseLine(wg *sync.WaitGroup, in chan string, out chan *Record) {
	cp := re.Copy()
	for l := range in {
		var line []string
		if parsed := cp.FindAllStringSubmatch(l, -1); len(parsed) == 1 {
			line = parsed[0]
		} else {
			continue
		}

		r := &Record{
			IP:        line[1],
			Method:    line[3],
			Filename:  line[4],
			Status:    line[5],
			Referer:   line[6],
			UserAgent: line[7],
		}

		r.TS, _ = time.Parse(timeFmt, line[2])
		out <- r
	}
	wg.Done()
}
