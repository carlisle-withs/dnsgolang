// Package report 承载 PDF 扫描报告与 XLSX 批量导出(Phase 9)。
// PDF 中文字体:优先环境变量 DNSSS_PDF_FONT 指定的 TTF,其次常见系统路径;
// 运行时用 fpdf.MakeFont 生成字体度量,避免仓库分发二进制字体文件。
package report

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/go-pdf/fpdf"

	"dnsss/internal/model"
	"dnsss/internal/risk"
)

// ScanReportSource 报告需要的数据访问(由 service 提供实现)。
type ScanReportSource interface {
	ScanResultsForJob(ctx context.Context, jobID uint64) ([]model.ScanResult, []model.TrustHost, []model.TrustDomain)
}

var (
	fontOnce  sync.Once
	fontErr   error
	fontReady bool
)

const fontFamily = "cjk"

func fontCandidates() []string {
	if v := os.Getenv("DNSSS_PDF_FONT"); v != "" {
		return []string{v}
	}
	return []string{
		"/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
		"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
		"/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
		"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", // 兜底(无中文,数字可用)
	}
}

var cachedFontBytes []byte

func ensureFont(pdf *fpdf.Fpdf) {
	fontOnce.Do(func() {
		for _, path := range fontCandidates() {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			cachedFontBytes = data
			fontReady = true
			return
		}
		fontErr = fmt.Errorf("未找到可用中文字体(设置 DNSSS_PDF_FONT 指向 TTF 文件)")
	})
	if fontErr == nil && cachedFontBytes != nil {
		pdf.AddUTF8FontFromBytes(fontFamily, "", cachedFontBytes)
	}
}

// BuildScanReportPDF 生成扫描报告 PDF:
// 任务信息 → KPI 摘要 → 风险分布 → 可疑主机明细(含 evidence 摘录)→ 方法统计。
func BuildScanReportPDF(ctx context.Context, src ScanReportSource, job model.ScanJob) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	ensureFont(pdf)
	if fontErr != nil {
		return nil, fontErr
	}
	pdf.SetFont(fontFamily, "", 12)
	pdf.AddPage()

	results, hosts, domains := src.ScanResultsForJob(ctx, job.ID)
	hostFqdns := map[uint64]string{}
	for _, h := range hosts {
		hostFqdns[h.ID] = h.FQDN
	}
	domainNames := map[uint64]string{}
	for _, d := range domains {
		domainNames[d.ID] = d.Domain
	}

	// 标题
	pdf.SetFontSize(20)
	pdf.Write(10, "DNS 所有权风险扫描报告")
	pdf.Ln(12)

	// 任务信息
	pdf.SetFontSize(13)
	pdf.Write(7, "一、任务信息")
	pdf.Ln(8)
	pdf.SetFontSize(11)
	writeKV(pdf, "任务编号", fmt.Sprintf("#%d", job.ID))
	writeKV(pdf, "环境", job.Environment)
	writeKV(pdf, "状态", job.Status)
	writeKV(pdf, "解析器", job.ResolverIP)
	writeKV(pdf, "创建时间", job.CreateTime.Format("2006-01-02 15:04:05"))
	if job.StartedAt != nil {
		writeKV(pdf, "开始时间", job.StartedAt.Format("2006-01-02 15:04:05"))
	}
	if job.FinishedAt != nil {
		writeKV(pdf, "结束时间", job.FinishedAt.Format("2006-01-02 15:04:05"))
	}
	pdf.Ln(3)

	// KPI 摘要
	pdf.SetFontSize(13)
	pdf.Write(7, "二、KPI 摘要")
	pdf.Ln(8)
	pdf.SetFontSize(11)
	writeKV(pdf, "扫描主机数", fmt.Sprintf("%d", job.TotalHosts))
	writeKV(pdf, "正常主机", fmt.Sprintf("%d", job.SuccessHosts-job.SuspiciousHosts))
	writeKV(pdf, "可疑主机", fmt.Sprintf("%d", job.SuspiciousHosts))
	writeKV(pdf, "错误主机", fmt.Sprintf("%d", job.ErrorHosts))
	if job.AvgLatencyMs != nil {
		writeKV(pdf, "平均延迟(ms)", fmt.Sprintf("%.2f", *job.AvgLatencyMs))
	}
	pdf.Ln(3)

	// 风险分布(类型 × 严重度矩阵)
	pdf.SetFontSize(13)
	pdf.Write(7, "三、风险分布")
	pdf.Ln(8)
	pdf.SetFontSize(11)
	typeCount := map[string]int{}
	severityCount := map[string]int{}
	methodCount := map[string]int{}
	suspiciousRows := []model.ScanResult{}
	for _, r := range results {
		if r.Status != model.ResultStatusSuspicious {
			continue
		}
		suspiciousRows = append(suspiciousRows, r)
		var rts []string
		if err := unmarshalJSON(r.RiskTypesTx, &rts); err == nil {
			for _, rt := range rts {
				typeCount[rt]++
				severityCount[risk.RiskSeverity[rt]]++
				if code := risk.MethodCodeForRisk(rt); code != "" {
					methodCount[code]++
				}
			}
		}
	}
	if len(typeCount) == 0 {
		pdf.Write(6, "未发现风险异常。")
		pdf.Ln(8)
	} else {
		for _, rt := range risk.RiskOrder {
			if typeCount[rt] == 0 {
				continue
			}
			writeKV(pdf, risk.RiskLabels[rt], fmt.Sprintf("%d 次(严重度 %s)", typeCount[rt], risk.RiskSeverity[rt]))
		}
	}
	pdf.Ln(3)

	// 可疑主机明细
	pdf.SetFontSize(13)
	pdf.Write(7, "四、可疑主机明细")
	pdf.Ln(8)
	pdf.SetFontSize(10)
	if len(suspiciousRows) == 0 {
		pdf.Write(6, "无")
		pdf.Ln(6)
	}
	for i, r := range suspiciousRows {
		if i >= 50 {
			pdf.Write(5, fmt.Sprintf("…… 其余 %d 条略", len(suspiciousRows)-50))
			pdf.Ln(6)
			break
		}
		fqdn := hostFqdns[r.HostID]
		domain := ""
		if r.DomainID != nil {
			domain = domainNames[*r.DomainID]
		}
		pdf.Write(5, fmt.Sprintf("%d. %s (域:%s)  严重度:%s  置信:%s", i+1, fqdn, domain, r.Severity, confidenceLabel(r.ConfidenceTier)))
		pdf.Ln(5)
		pdf.Write(5, "    "+truncate(r.SummaryMessage, 88))
		pdf.Ln(5)
	}

	// 方法统计
	pdf.Ln(3)
	pdf.SetFontSize(13)
	pdf.Write(7, "五、方法统计")
	pdf.Ln(8)
	pdf.SetFontSize(11)
	for _, m := range risk.MethodCatalog {
		writeKV(pdf, m.Label, fmt.Sprintf("%d 次命中", methodCount[m.Code]))
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeKV(pdf *fpdf.Fpdf, key, value string) {
	pdf.Write(6, key+"：")
	pdf.Write(6, value)
	pdf.Ln(6)
}

func confidenceLabel(tier string) string {
	switch tier {
	case "high_confidence":
		return "高置信异常"
	case "review_required":
		return "需复核异常"
	}
	return "-"
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}
