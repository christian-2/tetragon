// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package probemetrics

import (
	"sync"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

type Key struct {
	id     uint32
	attach string
}

type Stat struct {
	policy string
	missed float64
}

var (
	MissedProbes = metrics.NewBPFCounter(prometheus.NewDesc(
		prometheus.BuildFQName(consts.MetricsNamespace, "", "missed_probes_total"),
		"The total number of Tetragon probe missed per policy,probe.",
		[]string{"policy", "attach"}, nil,
	))

	lock  sync.Mutex
	stats = make(map[Key]Stat)
)

func Store(id uint32, policy, attach string, missed float64) {
	key := Key{id, attach}
	if stat, found := stats[key]; found {
		stat.missed = missed
		stats[key] = stat
	}

	lock.Lock()
	defer lock.Unlock()

	stats[key] = Stat{
		policy: policy,
		missed: missed,
	}
}

func Remove(id uint32, attach string) {
	lock.Lock()
	defer lock.Unlock()
	delete(stats, Key{id, attach})
}
