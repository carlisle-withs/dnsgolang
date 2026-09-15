package report

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/xuri/excelize/v2"

	"dnsss/internal/model"
)

// BatchExportSource 批量导出的数据访问。
type BatchExportSource interface {
	BatchResultsForExport(ctx context.Context, executionID uint64) ([]model.BatchResult, string, error)
}

// BuildBatchResultsXLSX 批量执行结果导出。
func BuildBatchResultsXLSX(ctx context.Context, src BatchExportSource, executionID uint64) ([]byte, error) {
	results, executionNo, err := src.BatchResultsForExport(ctx, executionID)
	if err != nil {
		return nil, err
	}
	f := excelize.NewFile()
	sheet := "结果明细"
	f.SetSheetName("Sheet1", sheet)
	headers := []string{"ID", "目标", "协议", "地区", "节点", "状态", "成功", "解析结果",
		"延迟(ms)", "结果码", "错误码", "错误信息", "检测时间"}
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(sheet, cell, h)
	}
	for row, r := range results {
		values := []any{
			r.ID, r.Target, r.Protocol, r.RegionCode, r.NodeCode, r.Status,
			r.Success, r.ResolvedTarget, derefAny(r.LatencyMs), r.ResultCode,
			r.ErrorCode, r.ErrorMessage, r.CreateTime.Format("2006-01-02 15:04:05.000"),
		}
		for col, v := range values {
			cell, _ := excelize.CoordinatesToCellName(col+1, row+2)
			f.SetCellValue(sheet, cell, v)
		}
	}
	style, err := f.NewStyle(&excelize.Style{Font: &excelize.Font{Bold: true}})
	if err == nil {
		f.SetCellStyle(sheet, "A1", "M1", style)
	}
	f.SetColWidth(sheet, "A", "M", 18)

	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		return nil, err
	}
	_ = executionNo
	return buf.Bytes(), nil
}

func derefAny(p *float64) any {
	if p == nil {
		return ""
	}
	return *p
}

func unmarshalJSON(s string, v any) error { return json.Unmarshal([]byte(s), v) }
