package registry

import (
	"bytes"
	"os"
	"strings"
	"sync"

	"www.velocidex.com/golang/regparser"
)

// HydrateRecordValues fills IndexRecord.V from hive files for a small delta set.
func HydrateRecordValues(hives []LocalHiveFile, recs []IndexRecord) {
	if len(hives) == 0 || len(recs) == 0 {
		return
	}
	cache := newHiveLookupCache(hives)
	defer cache.close()
	for i := range recs {
		if v, ok := cache.lookup(recs[i].K, recs[i].N); ok {
			recs[i].V = v
		}
	}
}

// HydrateValueChanges fills before/after display values from hive files.
func HydrateValueChanges(fromHives, toHives []LocalHiveFile, changes []ValueChange) {
	if len(changes) == 0 {
		return
	}
	from := newHiveLookupCache(fromHives)
	to := newHiveLookupCache(toHives)
	defer from.close()
	defer to.close()
	for i := range changes {
		if v, ok := from.lookup(changes[i].K, changes[i].N); ok {
			changes[i].V0 = v
		}
		if v, ok := to.lookup(changes[i].K, changes[i].N); ok {
			changes[i].V1 = v
		}
	}
}

type hiveLookupCache struct {
	hives []LocalHiveFile
	mu    sync.Mutex
	regs  map[string]*openHive
}

type openHive struct {
	data []byte
	reg  *regparser.Registry
}

func newHiveLookupCache(hives []LocalHiveFile) *hiveLookupCache {
	return &hiveLookupCache{hives: hives, regs: map[string]*openHive{}}
}

func (c *hiveLookupCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.regs = nil
}

func (c *hiveLookupCache) lookup(key, name string) (any, bool) {
	hf, rel, ok := matchHive(c.hives, key)
	if !ok {
		return nil, false
	}
	oh := c.open(hf.LocalPath)
	if oh == nil || oh.reg == nil {
		return nil, false
	}
	node := oh.reg.OpenKey(rel)
	if node == nil {
		return nil, false
	}
	want := strings.ToLower(name)
	for _, val := range node.Values() {
		if val == nil || strings.ToLower(val.ValueName()) != want {
			continue
		}
		raw, _ := valuePayload(val.ValueData(), val.TypeString())
		return raw, true
	}
	return nil, false
}

func (c *hiveLookupCache) open(path string) *openHive {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.regs == nil {
		return nil
	}
	if oh, ok := c.regs[path]; ok {
		return oh
	}
	data, err := os.ReadFile(path)
	if err != nil {
		c.regs[path] = nil
		return nil
	}
	reg, err := regparser.NewRegistry(bytes.NewReader(data))
	if err != nil {
		c.regs[path] = nil
		return nil
	}
	oh := &openHive{data: data, reg: reg}
	c.regs[path] = oh
	return oh
}

func matchHive(hives []LocalHiveFile, key string) (LocalHiveFile, string, bool) {
	bestIdx := -1
	bestLen := -1
	uk := strings.ToUpper(key)
	for i, h := range hives {
		p := strings.TrimRight(h.Prefix, `\`)
		up := strings.ToUpper(p)
		if uk == up || strings.HasPrefix(uk, up+`\`) {
			if len(up) > bestLen {
				bestLen = len(up)
				bestIdx = i
			}
		}
	}
	if bestIdx < 0 {
		return LocalHiveFile{}, "", false
	}
	p := strings.TrimRight(hives[bestIdx].Prefix, `\`)
	rel := strings.TrimPrefix(key[len(p):], `\`)
	return hives[bestIdx], rel, true
}
