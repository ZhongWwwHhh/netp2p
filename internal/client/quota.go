package client

import (
	"context"
	"sort"
	"time"

	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/version"
	"github.com/netp2p/netp2p/internal/wire/pb"
)

const defaultQuotaReportInterval = 30 * time.Second

// RunQuotaReporting periodically flushes locally observed usage to the manager.
// Reporting is best effort: a failed flush keeps the deltas for the next tick
// rather than losing them.
func (client *Client) RunQuotaReporting(ctx context.Context) {
	ticker := time.NewTicker(client.quotaReportInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			client.flushQuota(ctx)
			return
		case <-ticker.C:
			client.flushQuota(ctx)
		}
	}
}

func (client *Client) quotaReportInterval() time.Duration {
	client.mu.RLock()
	seconds := client.snapshot.State.Settings.QuotaReportIntervalSeconds
	client.mu.RUnlock()
	if seconds <= 0 {
		return defaultQuotaReportInterval
	}
	return time.Duration(seconds) * time.Second
}

func (client *Client) flushQuota(ctx context.Context) {
	client.mu.RLock()
	enforcer := client.quota
	managerID := client.manager.ID
	client.mu.RUnlock()
	if enforcer == nil {
		return
	}
	deltas := enforcer.DrainDeltas()
	if len(deltas) == 0 {
		return
	}
	ids := make([]string, 0, len(deltas))
	for id := range deltas {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	report := &pb.QuotaReport{
		PeerId:          client.node.Host.ID().String(),
		ReportedAt:      time.Now().UTC().Format(time.RFC3339Nano),
		ProtocolVersion: version.ProtocolVersion,
	}
	for _, id := range ids {
		report.Increments = append(report.Increments, &pb.BudgetIncrement{BudgetId: id, Bytes: deltas[id]})
	}
	sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.node.Send(sendCtx, managerID, p2p.QuotaProtocol, report); err != nil {
		// Restore the deltas so the next tick retries them.
		client.mu.RLock()
		enforcer := client.quota
		client.mu.RUnlock()
		if enforcer != nil {
			for id, bytes := range deltas {
				enforcer.RestoreDelta(id, bytes)
			}
		}
	}
}
