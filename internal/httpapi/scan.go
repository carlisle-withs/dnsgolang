package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"dnsss/internal/dto"
	"dnsss/internal/middleware"
	"dnsss/internal/report"
)

// registerScanRoutes /api/netprobe/dns-trust 扫描器部分(Phase 7)+ P9 报告导出。
func (a *API) registerScanRoutes(g *gin.RouterGroup) {
	g.GET("/scan-jobs", a.scanListJobs)
	g.POST("/scan-jobs", a.scanCreateJob)
	g.GET("/scan-jobs/:id", a.scanJobDetail)
	g.GET("/scan-jobs/:id/results", a.scanJobResults)
	g.GET("/scan-jobs/:id/report", a.scanJobReport)
	g.POST("/scan-jobs/:id/stop", a.scanJobStop)
	g.GET("/ownership-kpis", a.ownershipKPIs)
	g.GET("/monitor-profiles", a.monitorListProfiles)
	g.POST("/monitor-profiles", a.monitorCreateProfile)
	g.GET("/set-analysis", a.setAnalysis)
	g.GET("/hosts/:id/verdicts", a.hostVerdicts)
}

func (a *API) scanListJobs(c *gin.Context) {
	payload, err := a.svc.ListScanJobs(c.Request.Context(),
		c.Query("environment"), c.Query("status"),
		queryInt(c, "page", 1), queryInt(c, "page_size", 20))
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) scanCreateJob(c *gin.Context) {
	var body map[string]any
	if err := c.BindJSON(&body); err != nil {
		dto.Fail(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	userID, _ := middleware.UserID(c)
	job, err := a.svc.CreateScanJob(c.Request.Context(), body, &userID)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	fresh, _ := a.svc.GetScanJob(c.Request.Context(), job.ID)
	dto.Created(c, a.svc.ScanJobPayload(c.Request.Context(), *fresh))
}

func (a *API) scanJobDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "扫描任务不存在")
		return
	}
	job, err2 := a.svc.GetScanJob(c.Request.Context(), id)
	if err2 != nil {
		dto.Abort(c, err2)
		return
	}
	dto.OK(c, a.svc.ScanJobPayload(c.Request.Context(), *job))
}

func (a *API) scanJobResults(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "扫描任务不存在")
		return
	}
	payload, err2 := a.svc.ListScanResults(c.Request.Context(), id,
		queryInt(c, "page", 1), queryInt(c, "page_size", 20), c.Query("keyword"))
	if err2 != nil {
		dto.Abort(c, err2)
		return
	}
	dto.OK(c, payload)
}

// scanJobStop P9 前置:停止请求(与批量停止同语义,置终态标志)。
func (a *API) scanJobStop(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "扫描任务不存在")
		return
	}
	if err := a.svc.RequestScanStop(c.Request.Context(), id); err != nil {
		dto.Abort(c, err)
		return
	}
	job, _ := a.svc.GetScanJob(c.Request.Context(), id)
	dto.OK(c, a.svc.ScanJobPayload(c.Request.Context(), *job))
}

func (a *API) ownershipKPIs(c *gin.Context) {
	dto.OK(c, a.svc.BuildOwnershipKPIs(c.Request.Context(), c.Query("environment")))
}

func (a *API) hostVerdicts(c *gin.Context) {
	id, ok := pathID(c, "id")
	if !ok {
		return
	}
	payload, err := a.svc.BuildHostVerdicts(c.Request.Context(), id)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) monitorListProfiles(c *gin.Context) {
	payload, err := a.svc.ListMonitorProfiles(c.Request.Context(), c.Query("environment"))
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) monitorCreateProfile(c *gin.Context) {
	var body map[string]any
	if err := c.BindJSON(&body); err != nil {
		dto.Fail(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	userID, _ := middleware.UserID(c)
	payload, err := a.svc.CreateMonitorProfile(c.Request.Context(), body, &userID)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.Created(c, payload)
}

func (a *API) setAnalysis(c *gin.Context) {
	var jobID uint64
	if v := c.Query("jobId"); v != "" {
		jobID, _ = strconv.ParseUint(v, 10, 64)
	}
	riskTypes := []string{}
	if v := c.Query("riskTypes"); v != "" {
		riskTypes = strings.Split(v, ",")
	}
	dto.OK(c, a.svc.BuildSetAnalysis(c.Request.Context(),
		c.Query("environment"), orDefaultStr(c.Query("window"), "24h"),
		jobID, riskTypes, c.Query("operation"), queryInt(c, "page", 1), queryInt(c, "page_size", 20)))
}

// scanJobReport PDF 报告(P9)。
func (a *API) scanJobReport(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "扫描任务不存在")
		return
	}
	job, err2 := a.svc.GetScanJob(c.Request.Context(), id)
	if err2 != nil {
		dto.Abort(c, err2)
		return
	}
	if job.Status != "completed" {
		dto.Fail(c, http.StatusConflict, "仅已完成扫描任务支持导出风险报告")
		return
	}
	pdf, err := report.BuildScanReportPDF(c.Request.Context(), a.svc, *job)
	if err != nil {
		dto.Fail(c, http.StatusInternalServerError, "报告生成失败: "+err.Error())
		return
	}
	c.Header("Content-Type", "application/pdf")
	c.Header("Content-Disposition", "attachment; filename=scan-report-"+strconv.FormatUint(job.ID, 10)+".pdf")
	c.Data(http.StatusOK, "application/pdf", pdf)
}

// batchExportXLSX 批量执行结果导出(P9,新增能力接口)。
func (a *API) batchExportXLSX(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "批量执行不存在")
		return
	}
	xlsx, err := report.BuildBatchResultsXLSX(c.Request.Context(), a.svc, id)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", "attachment; filename=batch-results-"+strconv.FormatUint(id, 10)+".xlsx")
	c.Data(http.StatusOK, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", xlsx)
}

var _ = json.Marshal

func orDefaultStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// ---------- 探针注册与管理(Phase 8) ----------

func (a *API) probeAgentRegister(c *gin.Context) {
	var body map[string]any
	if err := c.BindJSON(&body); err != nil {
		dto.Fail(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	payload, err := a.svc.RegisterProbeAgent(c.Request.Context(), body,
		c.GetHeader("X-Probe-Token"),
		c.GetHeader("X-SSL-Client-Verify"), c.GetHeader("X-SSL-Client-S-DN"),
		c.ClientIP())
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.Created(c, payload)
}

func (a *API) probeAgentList(c *gin.Context) {
	dto.OK(c, gin.H{"results": a.svc.ListAgents(c.Request.Context())})
}

func (a *API) probeAgentDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "探针不存在")
		return
	}
	var agent struct{ ID uint64 }
	if err := a.db.Table("probe_agents").Select("id").Where("id = ?", id).Scan(&agent).Error; err != nil || agent.ID == 0 {
		dto.Fail(c, http.StatusBadRequest, "探针不存在")
		return
	}
	payload, err2 := a.svc.AgentPayloadByID(c.Request.Context(), id)
	if err2 != nil {
		dto.Abort(c, err2)
		return
	}
	dto.OK(c, payload)
}

func (a *API) probeAgentUpdate(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "探针不存在")
		return
	}
	var body map[string]any
	if err := c.BindJSON(&body); err != nil {
		dto.Fail(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	payload, err2 := a.svc.UpdateAgent(c.Request.Context(), id, body)
	if err2 != nil {
		dto.Abort(c, err2)
		return
	}
	dto.OK(c, payload)
}
