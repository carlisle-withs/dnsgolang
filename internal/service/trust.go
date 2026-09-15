package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"dnsss/internal/dto"
	"dnsss/internal/engine/dnsclient"
	"dnsss/internal/engine/prober"
	"dnsss/internal/model"
)

// ---------- manifest 解析(auto/json/yaml 子集) ----------

type manifestHost struct {
	FQDN           string `json:"fqdn"`
	AllowWildcard  bool   `json:"allow_wildcard"`
	AllowAXFR      bool   `json:"allow_axfr"`
	AllowRebind    bool   `json:"allow_rebind"`
	DNSSECExpected bool   `json:"dnssec_expected"`
	Enabled        bool   `json:"enabled"`
	Notes          string `json:"notes"`
}

type manifestItem struct {
	Domain      string        `json:"domain"`
	Owner       string        `json:"owner"`
	Importance  string        `json:"importance"`
	Environment string        `json:"environment"`
	Enabled     bool          `json:"enabled"`
	Notes       string        `json:"notes"`
	AllowWildcard bool        `json:"allow_wildcard"`
	AllowAXFR     bool        `json:"allow_axfr"`
	AllowRebind   bool        `json:"allow_rebind"`
	DNSSECExpected bool       `json:"dnssec_expected"`
	KeyHosts     []manifestHost `json:"key_hosts"`
}

// parseManifest 镜像 parse_manifest_text:JSON 数组/{"domains":[...]},
// 或 YAML 子集("- domain: X" 列表,含 key_hosts 子列表)。
func parseManifest(text, formatCode string) ([]manifestItem, string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, "", fmt.Errorf("主清单不能为空")
	}
	format := strings.ToLower(formatCode)
	if format == "" || format == "auto" {
		if len(text) > 0 && (text[0] == '[' || text[0] == '{') {
			format = "json"
		} else {
			format = "yaml"
		}
	}
	switch format {
	case "json":
		items, err := parseJSONManifest(text)
		if err != nil {
			return nil, "", err
		}
		return items, "json", nil
	case "yaml", "text":
		items, err := parseYAMLSubsetManifest(text)
		if err != nil {
			return nil, "", err
		}
		return items, "yaml", nil
	}
	return nil, "", fmt.Errorf("不支持的主清单格式: %s", format)
}

func parseJSONManifest(text string) ([]manifestItem, error) {
	var raw any
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, fmt.Errorf("主清单 JSON 解析失败: %v", err)
	}
	var list []any
	switch v := raw.(type) {
	case []any:
		list = v
	case map[string]any:
		if domains, ok := v["domains"].([]any); ok {
			list = domains
		} else if items, ok := v["items"].([]any); ok {
			list = items
		} else {
			return nil, fmt.Errorf("主清单结构无效")
		}
	default:
		return nil, fmt.Errorf("主清单结构无效")
	}
	data, _ := json.Marshal(list)
	var items []manifestItem
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("主清单结构无效")
	}
	return items, nil
}

// parseYAMLSubsetManifest 支持:
//
//	- domain: example.com
//	  owner: x
//	  key_hosts:
//	  - fqdn: www.example.com
//	- example.com          # 裸域名简写
func parseYAMLSubsetManifest(text string) ([]manifestItem, error) {
	type rawPair struct{ key, value string }
	items := []manifestItem{}
	var current *manifestItem
	var currentHost *manifestHost
	inHosts := false

	flushHost := func() {
		if current != nil && currentHost != nil {
			current.KeyHosts = append(current.KeyHosts, *currentHost)
			currentHost = nil
		}
	}
	flushItem := func() {
		flushHost()
		if current != nil {
			items = append(items, *current)
			current = nil
		}
	}
	for lineNo, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "---" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		pair := splitKV(trimmed)
		if indent == 0 && strings.HasPrefix(trimmed, "- ") {
			flushItem()
			inHosts = false
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			if pair := splitKV(rest); pair != nil && pair.key == "domain" {
				current = &manifestItem{Domain: pair.value, Importance: model.TrustImportanceHigh, Enabled: true}
			} else {
				current = &manifestItem{Domain: rest, Importance: model.TrustImportanceHigh, Enabled: true}
			}
			continue
		}
		if current == nil {
			if lineNo > 0 {
				continue
			}
			return nil, fmt.Errorf("主清单结构无效")
		}
		if pair == nil {
			continue
		}
		if indent == 0 {
			// 顶层 key(不支持裸 map 形式,除非作为单条)
			continue
		}
		isHostListHeader := pair.key == "key_hosts" || pair.key == "hosts"
		if isHostListHeader {
			flushHost()
			inHosts = true
			continue
		}
		if strings.HasPrefix(trimmed, "- ") && indent >= 2 {
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			rp := splitKV(rest)
			if inHosts {
				flushHost()
				host := manifestHost{Enabled: true, Notes: ""}
				if rp != nil && rp.key == "fqdn" {
					host.FQDN = rp.value
				} else {
					host.FQDN = rest
				}
				currentHost = &host
				continue
			}
		}
		if inHosts && currentHost != nil {
			applyManifestHostField(currentHost, pair.key, pair.value)
			continue
		}
		if !inHosts {
			applyManifestItemField(current, pair.key, pair.value)
		}
	}
	flushItem()
	if len(items) == 0 {
		return nil, fmt.Errorf("主清单结构无效")
	}
	return items, nil
}

func splitKV(s string) *struct{ key, value string } {
	idx := strings.Index(s, ":")
	if idx <= 0 {
		return nil
	}
	value := strings.TrimSpace(s[idx+1:])
	value = strings.Trim(value, `"'`)
	if i := strings.Index(value, " #"); i >= 0 {
		value = strings.TrimSpace(value[:i])
	}
	return &struct{ key, value string }{strings.TrimSpace(s[:idx]), value}
}

func applyManifestItemField(item *manifestItem, key, value string) {
	switch key {
	case "domain", "zone_domain":
		item.Domain = normalizeFQDN(value)
	case "owner":
		item.Owner = value
	case "importance":
		item.Importance = value
	case "environment":
		item.Environment = strings.ToLower(value)
	case "enabled":
		item.Enabled = value != "false"
	case "notes":
		item.Notes = value
	case "allow_wildcard":
		item.AllowWildcard = value == "true"
	case "allow_axfr":
		item.AllowAXFR = value == "true"
	case "allow_rebind":
		item.AllowRebind = value == "true"
	case "dnssec_expected":
		item.DNSSECExpected = value == "true"
	}
}

func applyManifestHostField(host *manifestHost, key, value string) {
	switch key {
	case "fqdn", "host", "name":
		host.FQDN = normalizeFQDN(value)
	case "allow_wildcard":
		host.AllowWildcard = value == "true"
	case "allow_axfr":
		host.AllowAXFR = value == "true"
	case "allow_rebind":
		host.AllowRebind = value == "true"
	case "dnssec_expected":
		host.DNSSECExpected = value == "true"
	case "enabled":
		host.Enabled = value != "false"
	case "notes":
		host.Notes = value
	}
}

func normalizeFQDN(v string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(v), "."))
}

// normalizeManifest 镜像 normalize_manifest_payload:补 apex 主机、统一环境校验。
func normalizeManifest(items []manifestItem) ([]manifestItem, string, error) {
	environment := ""
	out := make([]manifestItem, 0, len(items))
	for _, item := range items {
		item.Domain = normalizeFQDN(item.Domain)
		if item.Domain == "" {
			return nil, "", fmt.Errorf("主清单中的域名不能为空")
		}
		if item.Environment == "" {
			item.Environment = model.TrustEnvProd
		}
		if item.Environment != model.TrustEnvProd && item.Environment != model.TrustEnvLab {
			return nil, "", fmt.Errorf("不支持的环境: %s", item.Environment)
		}
		if environment != "" && environment != item.Environment {
			return nil, "", fmt.Errorf("单次导入只能包含同一环境的数据")
		}
		environment = item.Environment
		if item.Importance == "" {
			item.Importance = model.TrustImportanceHigh
		}
		seen := map[string]bool{}
		hosts := make([]manifestHost, 0, len(item.KeyHosts)+1)
		for _, h := range item.KeyHosts {
			h.FQDN = normalizeFQDN(h.FQDN)
			if h.FQDN == "" || seen[h.FQDN] {
				continue
			}
			seen[h.FQDN] = true
			hosts = append(hosts, h)
		}
		if !seen[item.Domain] {
			hosts = append([]manifestHost{{
				FQDN: item.Domain, Enabled: true, Notes: "manifest auto apex",
			}}, hosts...)
		}
		item.KeyHosts = hosts
		out = append(out, item)
	}
	if environment == "" {
		environment = model.TrustEnvProd
	}
	return out, environment, nil
}

// ---------- import-manifest ----------

// ImportTrustManifest 镜像 import_trust_manifest(upsert 语义 + 升级规则)。
func (s *Service) ImportTrustManifest(ctx context.Context, manifestText, formatCode, sourceLabel string, requestedBy *uint64) (map[string]any, error) {
	items, detectedFormat, err := parseManifest(manifestText, formatCode)
	if err != nil {
		return nil, dto.NewFieldError("manifest_text", err.Error())
	}
	items, environment, err := normalizeManifest(items)
	if err != nil {
		return nil, dto.NewFieldError("manifest_text", err.Error())
	}
	label := orDefault(sourceLabel, "manual manifest import")
	if len(label) > 128 {
		label = label[:128]
	}
	batch := &model.TrustCandidateBatch{
		SourceType: model.BatchSourceManifest, SourceLabel: label,
		Environment: environment, Status: model.BatchStatusDraft,
		RequestedByID: requestedBy, SummaryMessage: "主清单导入中",
		ManifestText: manifestText,
	}
	if err := s.gorm.WithContext(ctx).Create(batch).Error; err != nil {
		return nil, err
	}

	createdDomains, createdHosts, updatedDomains, updatedHosts := 0, 0, 0, 0
	domainCount, hostCount := 0, 0
	for _, item := range items {
		var domain model.TrustDomain
		tx := s.gorm.WithContext(ctx).
			Where(model.TrustDomain{Domain: item.Domain, Environment: item.Environment}).
			FirstOrCreate(&domain, model.TrustDomain{
				Domain: item.Domain, Owner: item.Owner, Importance: item.Importance,
				Enabled: item.Enabled, Environment: item.Environment, Notes: item.Notes,
			})
		if tx.Error != nil {
			return nil, tx.Error
		}
		domainCount++
		if tx.RowsAffected == 1 {
			createdDomains++
		} else {
			// upsert 升级规则:owner/importance(critical 提升)/notes/enabled 只增不减
			changed := false
			if domain.Owner == "" && item.Owner != "" {
				domain.Owner, changed = item.Owner, true
			}
			if item.Importance == model.TrustImportanceCritical && domain.Importance != model.TrustImportanceCritical {
				domain.Importance, changed = item.Importance, true
			} else if item.Importance == model.TrustImportanceHigh && domain.Importance == model.TrustImportanceMedium {
				domain.Importance, changed = item.Importance, true
			}
			if domain.Notes == "" && item.Notes != "" {
				domain.Notes, changed = item.Notes, true
			}
			if !domain.Enabled && item.Enabled {
				domain.Enabled, changed = true, true
			}
			if changed {
				s.gorm.WithContext(ctx).Model(&domain).Updates(map[string]any{
					"owner": domain.Owner, "importance": domain.Importance,
					"notes": domain.Notes, "enabled": domain.Enabled,
				})
				updatedDomains++
			}
		}
		for _, hostItem := range item.KeyHosts {
			var host model.TrustHost
			tx := s.gorm.WithContext(ctx).
				Where(model.TrustHost{DomainID: domain.ID, FQDN: hostItem.FQDN}).
				FirstOrCreate(&host, model.TrustHost{
					DomainID: domain.ID, FQDN: hostItem.FQDN,
					BaselineSource: model.TrustSourceManual, BaselineStatus: model.TrustStatusDraft,
					AllowWildcard: hostItem.AllowWildcard, AllowAXFR: hostItem.AllowAXFR,
					AllowRebind: hostItem.AllowRebind, DNSSECExpected: hostItem.DNSSECExpected,
					Enabled: hostItem.Enabled, Notes: hostItem.Notes,
				})
			if tx.Error != nil {
				return nil, tx.Error
			}
			hostCount++
			if tx.RowsAffected == 1 {
				createdHosts++
			} else {
				changed := false
				if host.Notes == "" && hostItem.Notes != "" {
					host.Notes, changed = hostItem.Notes, true
				}
				if !host.Enabled && hostItem.Enabled {
					host.Enabled, changed = true, true
				}
				if changed {
					s.gorm.WithContext(ctx).Model(&host).Updates(map[string]any{"notes": host.Notes, "enabled": host.Enabled})
					updatedHosts++
				}
			}
		}
	}
	s.gorm.WithContext(ctx).Model(batch).Updates(map[string]any{
		"summary_message": fmt.Sprintf("主清单导入完成: %d 个域名 / %d 个主机", domainCount, hostCount),
		"meta_text": marshalJSON(map[string]any{
			"format": detectedFormat, "environment": environment,
			"createdDomainCount": createdDomains, "updatedDomainCount": updatedDomains,
			"createdHostCount": createdHosts, "updatedHostCount": updatedHosts,
			"domainCount": domainCount, "hostCount": hostCount,
		}),
	})
	return map[string]any{
		"batchId": batch.ID, "environment": environment,
		"createdDomainCount": createdDomains, "updatedDomainCount": updatedDomains,
		"createdHostCount": createdHosts, "updatedHostCount": updatedHosts,
		"domainCount": domainCount, "hostCount": hostCount,
	}, nil
}

// ---------- discover-candidates ----------

type discoveryRow struct {
	Section  string
	RRName   string
	RRType   string
	RRValue  string
	TTL      *int
}

type discoveryPayload struct {
	host      model.TrustHost
	rows      []discoveryRow
	nsValues  []string
	summary   map[string]any
}

// buildHostDiscoveryPlan 镜像 build_host_discovery_plan(apex/NS 主机/子域三类)。
func buildHostDiscoveryPlan(host model.TrustHost, zoneDomain string) []prober.QueryStep {
	notes := strings.ToLower(host.Notes)
	isApex := normalizeFQDN(host.FQDN) == normalizeFQDN(zoneDomain)
	isNSHost := strings.Contains(notes, "role=ns_host") || strings.HasPrefix(notes, "ns host") || strings.HasPrefix(host.FQDN, "ns")
	udp := func(name, rtype string) prober.QueryStep {
		return prober.QueryStep{QueryName: name, RecordType: rtype, Transport: "udp", ServerMode: "resolver", RepeatCount: 1, EDNS: true}
	}
	if isApex {
		return []prober.QueryStep{
			udp(zoneDomain, "A"), udp(zoneDomain, "AAAA"), udp(zoneDomain, "NS"), udp(zoneDomain, "SOA"),
			{QueryName: zoneDomain, RecordType: "A", Transport: "udp", ServerMode: "resolver", RepeatCount: 1, EDNS: true, RandomLabel: true},
			{QueryName: zoneDomain, RecordType: "AXFR", Transport: "tcp", ServerMode: "authoritative", RepeatCount: 1, EDNS: false},
		}
	}
	if isNSHost {
		return []prober.QueryStep{udp(host.FQDN, "A"), udp(host.FQDN, "AAAA")}
	}
	return []prober.QueryStep{udp(host.FQDN, "A"), udp(host.FQDN, "AAAA"), udp(host.FQDN, "CNAME")}
}

// executeDiscoveryHost 本地执行单主机发现计划(镜像 _execute_discovery_host_locally)。
func executeDiscoveryHost(ctx context.Context, host model.TrustHost, zoneDomain, resolver string, timeout float64) discoveryPayload {
	payload := discoveryPayload{host: host, rows: []discoveryRow{}, nsValues: []string{},
		summary: map[string]any{}}
	plan := buildHostDiscoveryPlan(host, zoneDomain)
	options := map[string]any{
		"resolver": resolver, "record_type": "A", "timeout": timeout,
		"transport": "udp", "server_mode": "resolver", "compare_with_trust": false,
		"query_plan": planToAny(plan),
	}
	result := prober.ExecuteDNS(ctx, host.FQDN, options)
	observation, _ := result.Detail["observation"].(map[string]any)
	if observation != nil {
		if wildcard, ok := observation["wildcard_hit"].(bool); ok && wildcard {
			payload.summary["wildcardHit"] = true
		}
		if label, ok := observation["random_label"].(string); ok && label != "" {
			payload.summary["randomLabel"] = label
		}
		if axfr, ok := observation["axfr_success"].(bool); ok && axfr {
			payload.summary["axfrSuccess"] = true
		}
		if count, ok := observation["axfr_record_count"].(float64); ok {
			payload.summary["axfrRecordCount"] = int(count)
		}
	}
	if !result.Success && result.ErrorCode != "" && result.ErrorCode != "dns_failed" {
		payload.summary["errors"] = []string{result.ErrorMessage}
	}
	// 逐步执行计划收集记录行(random_label/AXFR 步不产生候选,与原版一致)
	for _, planned := range plan {
		if planned.RandomLabel || planned.RecordType == "AXFR" {
			continue
		}
		res := dnsclient.RunQuery(ctx, dnsclient.Spec{
			QueryName: planned.QueryName, RecordType: planned.RecordType, ResolverIP: resolver,
			Timeout: timeout, Transport: planned.Transport, ServerMode: planned.ServerMode,
			EDNS: planned.EDNS, RecursionDesired: true,
		})
		for section, lines := range map[string][]string{"answer": res.Answer, "authority": res.Authority, "additional": res.Additional} {
			for _, line := range lines {
				rr := parseRRLine(line, section)
				if rr == nil {
					continue
				}
				payload.rows = append(payload.rows, *rr)
				if rr.RRType == "NS" {
					payload.nsValues = append(payload.nsValues, strings.Trim(rr.RRValue, "."))
				}
			}
		}
	}
	return payload
}

func planToAny(plan []prober.QueryStep) []any {
	data, _ := json.Marshal(plan)
	var out []any
	_ = json.Unmarshal(data, &out)
	return out
}

// parseRRLine 镜像 parse_rr_line:"name TTL IN TYPE VALUE"。
func parseRRLine(line, section string) *discoveryRow {
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 4 {
		return nil
	}
	rrname := normalizeFQDN(parts[0])
	cursor := 1
	var ttl *int
	if cursor < len(parts) {
		if n, err := strconv.Atoi(parts[cursor]); err == nil {
			ttl = &n
			cursor++
		}
	}
	if cursor < len(parts) && strings.EqualFold(parts[cursor], "IN") {
		cursor++
	}
	if cursor >= len(parts) {
		return nil
	}
	rrtype := strings.ToUpper(parts[cursor])
	rrvalue := strings.TrimSpace(strings.Join(parts[cursor+1:], " "))
	return &discoveryRow{Section: section, RRName: rrname, RRType: rrtype, RRValue: rrvalue, TTL: ttl}
}

// DiscoverCandidates 镜像 discover_candidate_records(队列式 NS 主机扩散)。
func (s *Service) DiscoverCandidates(ctx context.Context, environment string, domainIDs, hostIDs []uint64, resolver string, timeout float64, sourceLabel string, requestedBy *uint64) (map[string]any, error) {
	if resolver == "" {
		resolver = "8.8.8.8"
	}
	if timeout <= 0 {
		timeout = 3
	}
	query := s.gorm.WithContext(ctx).
		Joins("JOIN dns_trust_domains d ON d.id = dns_trust_hosts.domain_id").
		Where("dns_trust_hosts.enabled = 1 AND d.enabled = 1 AND d.environment = ?", environment)
	if len(domainIDs) > 0 {
		query = query.Where("dns_trust_hosts.domain_id IN ?", domainIDs)
	}
	if len(hostIDs) > 0 {
		query = query.Where("dns_trust_hosts.id IN ?", hostIDs)
	}
	var hosts []model.TrustHost
	if err := query.Order("d.domain ASC, dns_trust_hosts.fqdn ASC").Find(&hosts).Error; err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, dto.NewFieldError("environment", "没有可发现的可信主机")
	}
	label := orDefault(sourceLabel, "dns candidate discovery")
	batch := &model.TrustCandidateBatch{
		SourceType: model.BatchSourceDiscovery, SourceLabel: label,
		Environment: environment, Status: model.BatchStatusDraft,
		RequestedByID: requestedBy, SummaryMessage: "候选发现执行中",
	}
	if err := s.gorm.WithContext(ctx).Create(batch).Error; err != nil {
		return nil, err
	}

	domains := map[uint64]model.TrustDomain{}
	var domainRows []model.TrustDomain
	s.gorm.WithContext(ctx).Find(&domainRows)
	for _, d := range domainRows {
		domains[d.ID] = d
	}

	processed := map[uint64]bool{}
	queue := append([]model.TrustHost{}, hosts...)
	candidateSeen := map[string]bool{}
	candidateRows := []model.TrustCandidateRecord{}
	discoveredNSHosts := []string{}
	for len(queue) > 0 {
		host := queue[0]
		queue = queue[1:]
		if processed[host.ID] {
			continue
		}
		processed[host.ID] = true
		zoneDomain := host.FQDN
		if domain, ok := domains[host.DomainID]; ok {
			zoneDomain = domain.Domain
		}
		ctxExec, cancel := context.WithTimeout(ctx, 30*time.Second)
		payload := executeDiscoveryHost(ctxExec, host, zoneDomain, resolver, timeout)
		cancel()
		for _, row := range payload.rows {
			key := fmt.Sprintf("%d|%s|%s|%s|%s", host.ID, row.Section, row.RRName, row.RRType, strings.TrimSpace(row.RRValue))
			if candidateSeen[key] {
				continue
			}
			candidateSeen[key] = true
			candidateRows = append(candidateRows, model.TrustCandidateRecord{
				BatchID: batch.ID, HostID: host.ID, Status: model.CandidateStatusDraft,
				Section: row.Section, RRName: row.RRName, RRType: row.RRType, RRValue: row.RRValue,
				TTLMin: row.TTL, TTLMax: row.TTL, IsRequired: true,
			})
		}
		for _, nsName := range payload.nsValues {
			if nsName == "" {
				continue
			}
			var nsHost model.TrustHost
			tx := s.gorm.WithContext(ctx).
				Where(model.TrustHost{DomainID: host.DomainID, FQDN: nsName}).
				FirstOrCreate(&nsHost, model.TrustHost{
					DomainID: host.DomainID, FQDN: nsName,
					BaselineSource: model.TrustSourceManual, BaselineStatus: model.TrustStatusDraft,
					Enabled: true, Notes: "role=ns_host; auto discovered from apex NS",
				})
			if tx.Error == nil && tx.RowsAffected == 1 {
				discoveredNSHosts = append(discoveredNSHosts, nsHost.FQDN)
			}
			if tx.Error == nil && !processed[nsHost.ID] {
				queue = append(queue, nsHost)
			}
		}
	}
	if len(candidateRows) > 0 {
		if err := s.gorm.WithContext(ctx).CreateInBatches(candidateRows, 500).Error; err != nil {
			return nil, err
		}
	}
	s.gorm.WithContext(ctx).Model(batch).Updates(map[string]any{
		"summary_message": fmt.Sprintf("候选发现完成: %d 主机 / %d 条候选记录", len(processed), len(candidateRows)),
		"meta_text": marshalJSON(map[string]any{
			"resolver": resolver, "timeout": timeout,
			"processedHostCount": len(processed), "candidateCount": len(candidateRows),
			"discoveredNsHosts": discoveredNSHosts,
		}),
	})
	return map[string]any{
		"batchId": batch.ID, "processedHostCount": len(processed),
		"candidateCount": len(candidateRows), "discoveredNsHostCount": len(discoveredNSHosts),
	}, nil
}

// ---------- 审批 ----------

// ReviewHostCandidates 镜像 review_host_candidates(approve 时重建 baseline)。
func (s *Service) ReviewHostCandidates(ctx context.Context, hostID, batchID uint64, reviewer *uint64, approve bool, reviewNote string, refreshBatch bool) (map[string]any, error) {
	var host model.TrustHost
	if err := s.gorm.WithContext(ctx).First(&host, hostID).Error; err != nil {
		return nil, dto.NewAPIError(400, "可信主机不存在")
	}
	var batch model.TrustCandidateBatch
	if err := s.gorm.WithContext(ctx).First(&batch, batchID).Error; err != nil {
		return nil, dto.NewAPIError(400, "候选批次不存在")
	}
	var records []model.TrustCandidateRecord
	s.gorm.WithContext(ctx).
		Where("batch_id = ? AND host_id = ? AND status = ?", batchID, hostID, model.CandidateStatusDraft).
		Find(&records)
	if len(records) == 0 {
		return nil, dto.NewAPIError(400, "当前主机在该批次下没有待审核候选")
	}
	now := time.Now()
	status := model.CandidateStatusRejected
	if approve {
		status = model.CandidateStatusApproved
		s.gorm.WithContext(ctx).Where("host_id = ?", host.ID).Delete(&model.TrustRecordBaseline{})
		baselines := make([]model.TrustRecordBaseline, 0, len(records))
		for _, r := range records {
			baselines = append(baselines, model.TrustRecordBaseline{
				HostID: host.ID, Section: r.Section, RRName: r.RRName,
				RRType: r.RRType, RRValue: r.RRValue, RRHash: rrHash(host.ID, r.Section, r.RRName, r.RRType, r.RRValue),
				TTLMin: r.TTLMin, TTLMax: r.TTLMax, IsRequired: r.IsRequired,
			})
		}
		if err := s.gorm.WithContext(ctx).CreateInBatches(baselines, 200).Error; err != nil {
			return nil, err
		}
		hostUpdates := map[string]any{"baseline_status": model.TrustStatusTrusted}
		if s.hostEnvironment(ctx, host.DomainID) == model.TrustEnvProd {
			hostUpdates["baseline_source"] = model.TrustSourceManual
		}
		s.gorm.WithContext(ctx).Model(&host).Updates(hostUpdates)
	}
	s.gorm.WithContext(ctx).Model(&model.TrustCandidateRecord{}).
		Where("id IN ?", recordIDs(records)).
		Updates(map[string]any{
			"status": status, "reviewed_by_id": reviewer,
			"reviewed_at": now, "review_note": reviewNote,
		})
	if refreshBatch {
		s.refreshCandidateBatchStatus(ctx, &batch, reviewer, approve)
	}
	var baselineCount int64
	s.gorm.WithContext(ctx).Model(&model.TrustRecordBaseline{}).Where("host_id = ?", host.ID).Count(&baselineCount)
	return map[string]any{
		"hostId": host.ID, "batchId": batch.ID, "approved": approve,
		"recordCount": len(records), "baselineCount": baselineCount,
	}, nil
}

// rrHash 记录唯一键哈希(等价原 (host,section,name,type,value) 联合唯一)。
func rrHash(hostID uint64, section, name, rrtype, value string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s|%s|%s", hostID, section, name, stringsUpper(rrtype), strings.TrimSpace(value))))
	return hex.EncodeToString(sum[:])
}

func sortIDs(ids []uint64) {
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j] < ids[j-1]; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
}

func recordIDs(records []model.TrustCandidateRecord) []uint64 {
	ids := make([]uint64, 0, len(records))
	for _, r := range records {
		ids = append(ids, r.ID)
	}
	return ids
}

// hostEnvironment 查主机所属环境。
func (s *Service) hostEnvironment(ctx context.Context, domainID uint64) string {
	var domain model.TrustDomain
	if err := s.gorm.WithContext(ctx).Where("id = ?", domainID).First(&domain).Error; err != nil {
		return model.TrustEnvProd
	}
	return domain.Environment
}

func (s *Service) refreshCandidateBatchStatus(ctx context.Context, batch *model.TrustCandidateBatch, reviewer *uint64, approve bool) {
	var counts []struct {
		Status string
		Count  int
	}
	s.gorm.WithContext(ctx).Model(&model.TrustCandidateRecord{}).
		Where("batch_id = ?", batch.ID).Select("status, COUNT(*) AS count").
		Group("status").Scan(&counts)
	status := model.BatchStatusDraft
	hasDraft, hasApproved := false, false
	total := 0
	for _, c := range counts {
		total += c.Count
		switch c.Status {
		case model.CandidateStatusDraft:
			hasDraft = true
		case model.CandidateStatusApproved:
			hasApproved = true
		}
	}
	switch {
	case total == 0:
		status = model.BatchStatusDraft
	case hasDraft:
		status = model.BatchStatusDraft
	case hasApproved:
		status = model.BatchStatusApproved
	default:
		status = model.BatchStatusRejected
	}
	updates := map[string]any{"status": status}
	if status == model.BatchStatusApproved && approve {
		updates["approved_by_id"] = reviewer
		updates["approved_at"] = time.Now()
	}
	s.gorm.WithContext(ctx).Model(batch).Updates(updates)
}

// BulkReviewHostCandidates 镜像 bulk_review_host_candidates。
func (s *Service) BulkReviewHostCandidates(ctx context.Context, batchID uint64, reviewer *uint64, approve bool, reviewNote string, hostIDs, domainIDs []uint64) (map[string]any, error) {
	var batch model.TrustCandidateBatch
	if err := s.gorm.WithContext(ctx).First(&batch, batchID).Error; err != nil {
		return nil, dto.NewAPIError(400, "候选批次不存在")
	}
	query := s.gorm.WithContext(ctx).Model(&model.TrustHost{}).
		Joins("JOIN dns_trust_candidate_records cr ON cr.host_id = dns_trust_hosts.id").
		Where("cr.batch_id = ? AND cr.status = ?", batchID, model.CandidateStatusDraft)
	if len(hostIDs) > 0 {
		query = query.Where("dns_trust_hosts.id IN ?", hostIDs)
	}
	if len(domainIDs) > 0 {
		query = query.Where("dns_trust_hosts.domain_id IN ?", domainIDs)
	}
	var targetIDs []uint64
	// 注意:DISTINCT 与 ORDER BY 非选择列在 MySQL 8 会报 3065,先取 id 再排序
	if err := query.Distinct().Pluck("dns_trust_hosts.id", &targetIDs).Error; err != nil {
		return nil, err
	}
	if len(targetIDs) == 0 {
		return nil, dto.NewAPIError(400, "当前筛选范围内没有待审核候选")
	}
	sortIDs(targetIDs)
	reviewedCount, recordCount := 0, 0
	for _, hostID := range targetIDs {
		payload, err := s.ReviewHostCandidates(ctx, hostID, batchID, reviewer, approve, reviewNote, false)
		if err != nil {
			slog.Warn("批量审批单主机失败", "host_id", hostID, "error", err)
			continue
		}
		reviewedCount++
		if rc, ok := payload["recordCount"].(int); ok {
			recordCount += rc
		}
	}
	s.refreshCandidateBatchStatus(ctx, &batch, reviewer, approve)
	s.gorm.WithContext(ctx).First(&batch, batchID)
	return map[string]any{
		"batchId": batch.ID, "approved": approve,
		"hostCount": reviewedCount, "recordCount": recordCount,
		"status": batch.Status,
	}, nil
}

// ---------- build-jobs ----------

// CreateTrustBuildJob 创建构建任务并异步执行(断点 = processed_chunks)。
func (s *Service) CreateTrustBuildJob(ctx context.Context, inputPath, environment string, limit, chunkSize, maxHostsPerDomain int, resolver string, timeout float64, sourceLabel string, importOnly, autoApprove bool, requestedBy *uint64) (*model.TrustBuildJob, error) {
	if strings.TrimSpace(inputPath) == "" {
		return nil, dto.NewFieldError("input_path", "请输入域名文件路径")
	}
	if chunkSize <= 0 {
		chunkSize = 300
	}
	if maxHostsPerDomain <= 0 {
		maxHostsPerDomain = 3
	}
	if resolver == "" {
		resolver = "223.5.5.5"
	}
	job := &model.TrustBuildJob{
		Environment: environment, Status: model.BuildStatusPending,
		RequestedByID: requestedBy, InputPath: strings.TrimSpace(inputPath),
		SourceLabel: sourceLabel, ResolverIP: resolver, TimeoutSeconds: timeout,
		ChunkSize: chunkSize, MaxHostsPerDomain: maxHostsPerDomain,
		ImportOnly: importOnly, AutoApprove: autoApprove,
	}
	if limit > 0 {
		job.LimitCount = &limit
	}
	if err := s.gorm.WithContext(ctx).Create(job).Error; err != nil {
		return nil, err
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.pool <- struct{}{}
		defer func() { <-s.pool }()
		if err := s.RunTrustBuildJob(context.Background(), job.ID); err != nil {
			slog.Error("可信库构建任务失败", "job_id", job.ID, "error", err)
		}
	}()
	return job, nil
}

// RunTrustBuildJob 执行构建:读文件 → 分片 → 导入/发现/审批(断点续跑)。
func (s *Service) RunTrustBuildJob(ctx context.Context, jobID uint64) error {
	var job model.TrustBuildJob
	if err := s.gorm.WithContext(ctx).First(&job, jobID).Error; err != nil {
		return err
	}
	now := time.Now()
	s.gorm.WithContext(ctx).Model(&job).Updates(map[string]any{
		"status": model.BuildStatusRunning, "started_at": now, "current_chunk": job.ProcessedChunks,
	})
	lines, err := readDomainFile(job.InputPath)
	if err != nil {
		s.finishBuildJob(ctx, &job, model.BuildStatusFailed, fmt.Sprintf("读取输入文件失败: %v", err))
		return nil
	}
	if job.LimitCount != nil && *job.LimitCount > 0 && len(lines) > *job.LimitCount {
		lines = lines[:*job.LimitCount]
	}
	chunkSize := job.ChunkSize
	totalChunks := (len(lines) + chunkSize - 1) / chunkSize
	s.gorm.WithContext(ctx).Model(&job).Updates(map[string]any{
		"total_input_hosts": len(lines), "total_domains": len(lines), "total_chunks": totalChunks,
	})
	for i := job.ProcessedChunks; i < totalChunks; i++ {
		chunk := lines[i*chunkSize : min((i+1)*chunkSize, len(lines))]
		manifest := buildChunkManifest(chunk)
		importPayload, err := s.ImportTrustManifest(ctx, manifest, "json", orDefault(job.SourceLabel, "build-job"), job.RequestedByID)
		if err != nil {
			s.finishBuildJob(ctx, &job, model.BuildStatusFailed, fmt.Sprintf("分片 %d 导入失败: %v", i+1, err))
			return nil
		}
		importedDomains, _ := importPayload["createdDomainCount"].(int)
		importedHosts, _ := importPayload["createdHostCount"].(int)
		discoveredHosts, candidateCount := 0, 0
		approvedHosts := 0
		if !job.ImportOnly {
			discoverPayload, err := s.DiscoverCandidates(ctx, job.Environment, nil, nil, job.ResolverIP, job.TimeoutSeconds, orDefault(job.SourceLabel, "build-job"), job.RequestedByID)
			if err == nil {
				if c, ok := discoverPayload["candidateCount"].(int); ok {
					candidateCount = c
				}
				if job.AutoApprove {
					if batchIDValue, ok := discoverPayload["batchId"].(uint64); ok {
						bulkPayload, err := s.BulkReviewHostCandidates(ctx, batchIDValue, job.RequestedByID, true, "build-job auto approve", nil, nil)
						if err == nil {
							if hc, ok := bulkPayload["hostCount"].(int); ok {
								approvedHosts = hc
							}
						}
					}
				}
			}
		}
		var trustedCount, draftCount int64
		countRows := []struct {
			Status string
			Count  int64
		}{}
		s.gorm.WithContext(ctx).Raw(`SELECT h.baseline_status AS status, COUNT(*) AS count
			FROM dns_trust_hosts h JOIN dns_trust_domains d ON d.id = h.domain_id
			WHERE d.environment = ? GROUP BY h.baseline_status`, job.Environment).Scan(&countRows)
		for _, row := range countRows {
			if row.Status == model.TrustStatusTrusted {
				trustedCount = row.Count
			} else {
				draftCount += row.Count
			}
		}
		s.gorm.WithContext(ctx).Model(&job).Updates(map[string]any{
			"processed_chunks": i + 1, "current_chunk": i + 1,
			"imported_domains": job.ImportedDomains + importedDomains,
			"imported_hosts":   job.ImportedHosts + importedHosts,
			"discovered_hosts": job.DiscoveredHosts + discoveredHosts,
			"candidate_records": job.CandidateRecords + candidateCount,
			"approved_hosts":   job.ApprovedHosts + approvedHosts,
			"trusted_hosts":    trustedCount,
			"draft_hosts":      draftCount,
			"summary_message": fmt.Sprintf("已处理 %d/%d 分片", i+1, totalChunks),
		})
		if err := s.gorm.WithContext(ctx).First(&job, jobID).Error; err != nil {
			return err
		}
	}
	s.finishBuildJob(ctx, &job, model.BuildStatusCompleted, "")
	return nil
}

func (s *Service) finishBuildJob(ctx context.Context, job *model.TrustBuildJob, status, errMsg string) {
	now := time.Now()
	updates := map[string]any{"status": status, "finished_at": now, "last_error": errMsg}
	if status == model.BuildStatusCompleted {
		updates["summary_message"] = fmt.Sprintf("构建完成: %d 域名 / %d 主机", job.ImportedDomains, job.ImportedHosts)
	}
	s.gorm.WithContext(ctx).Model(job).Updates(updates)
}

// buildChunkManifest 每行一个域名 → JSON manifest。
func buildChunkManifest(domains []string) string {
	items := make([]manifestItem, 0, len(domains))
	for _, d := range domains {
		d = normalizeFQDN(d)
		if d == "" {
			continue
		}
		items = append(items, manifestItem{Domain: d, Importance: model.TrustImportanceHigh, Enabled: true, Environment: model.TrustEnvProd})
	}
	data, _ := json.Marshal(items)
	return string(data)
}

func readDomainFile(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := []string{}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RetryTrustBuildJob 重试(从 processed_chunks 断点续跑)。
func (s *Service) RetryTrustBuildJob(ctx context.Context, jobID uint64, requestedBy *uint64) (*model.TrustBuildJob, error) {
	job, err := s.GetTrustBuildJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if job.Status == model.BuildStatusRunning {
		return nil, dto.NewAPIError(400, "任务仍在执行中")
	}
	s.gorm.WithContext(ctx).Model(job).Updates(map[string]any{
		"status": model.BuildStatusPending, "last_error": "", "finished_at": nil,
	})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.pool <- struct{}{}
		defer func() { <-s.pool }()
		if err := s.RunTrustBuildJob(context.Background(), jobID); err != nil {
			slog.Error("可信库构建重试失败", "job_id", jobID, "error", err)
		}
	}()
	return s.GetTrustBuildJob(ctx, jobID)
}

// GetTrustBuildJob 详情。
func (s *Service) GetTrustBuildJob(ctx context.Context, jobID uint64) (*model.TrustBuildJob, error) {
	var job model.TrustBuildJob
	if err := s.gorm.WithContext(ctx).First(&job, jobID).Error; err != nil {
		return nil, dto.NewAPIError(400, "构建任务不存在")
	}
	return &job, nil
}
