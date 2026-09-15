package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"dnsss/internal/dto"
	"dnsss/internal/middleware"
	"dnsss/internal/model"
)

// registerTrustRoutes /api/netprobe/dns-trust/*(Phase 6:可信库)
func (a *API) registerTrustRoutes(r *gin.Engine) {
	g := r.Group("/api/netprobe/dns-trust")
	g.Use(a.requireTrustAuth)
	{
		g.GET("/domains", a.trustListDomains)
		g.POST("/domains", a.trustCreateDomain)
		g.GET("/hosts", a.trustListHosts)
		g.POST("/hosts", a.trustCreateHost)
		g.GET("/hosts/bulk-approve", a.notAllowed)
		g.POST("/hosts/bulk-approve", a.trustBulkApprove)
		g.GET("/hosts/:id/baseline", a.trustHostBaseline)
		g.GET("/hosts/:id/candidates", a.trustHostCandidates)
		g.POST("/hosts/:id/approve", a.trustHostApprove)
		g.POST("/hosts/:id/reject", a.trustHostReject)
		g.GET("/hosts/:id/snapshots", a.trustHostSnapshots)
		g.POST("/import-manifest", a.trustImportManifest)
		g.POST("/discover-candidates", a.trustDiscoverCandidates)
		g.GET("/build-jobs", a.trustListBuildJobs)
		g.POST("/build-jobs", a.trustCreateBuildJob)
		g.GET("/build-jobs/:id", a.trustBuildJobDetail)
		g.POST("/build-jobs/:id/retry", a.trustBuildJobRetry)
	}
}

// requireTrustAuth dns-trust 全部要求登录(比原系统更严,安全修复项)。
func (a *API) requireTrustAuth(c *gin.Context) {
	if _, ok := middleware.UserID(c); !ok {
		dto.Fail(c, http.StatusForbidden, dto.ErrLoginRequired.Error())
		return
	}
	c.Next()
}

func (a *API) notAllowed(c *gin.Context) {
	dto.Fail(c, http.StatusMethodNotAllowed, "Method not allowed")
}

func pathID(c *gin.Context, name string) (uint64, bool) {
	id, err := strconv.ParseUint(c.Param(name), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "可信主机不存在")
		return 0, false
	}
	return id, true
}

func (a *API) trustListDomains(c *gin.Context) {
	payload, err := a.svc.ListTrustDomains(c.Request.Context(),
		c.Query("environment"), c.Query("keyword"), c.Query("id"),
		queryInt(c, "page", 1), queryInt(c, "page_size", 20))
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) trustCreateDomain(c *gin.Context) {
	var body map[string]any
	if err := c.BindJSON(&body); err != nil {
		dto.Fail(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	payload, err := a.svc.CreateTrustDomain(c.Request.Context(), body)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) trustListHosts(c *gin.Context) {
	_, withPageSize := c.Request.URL.Query()["page_size"]
	payload, err := a.svc.ListTrustHosts(c.Request.Context(),
		c.Query("domain_id"), c.Query("environment"), c.Query("keyword"),
		stringsLower(c.Query("ids_only")), withPageSize,
		queryInt(c, "page", 1), queryInt(c, "page_size", 20))
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) trustCreateHost(c *gin.Context) {
	var body map[string]any
	if err := c.BindJSON(&body); err != nil {
		dto.Fail(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	payload, err := a.svc.CreateTrustHost(c.Request.Context(), body)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) trustHostBaseline(c *gin.Context) {
	id, ok := pathID(c, "id")
	if !ok {
		return
	}
	payload, err := a.svc.BuildHostBaseline(c.Request.Context(), id)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) trustHostCandidates(c *gin.Context) {
	id, ok := pathID(c, "id")
	if !ok {
		return
	}
	payload, err := a.svc.BuildHostCandidates(c.Request.Context(), id)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) trustHostSnapshots(c *gin.Context) {
	id, ok := pathID(c, "id")
	if !ok {
		return
	}
	payload, err := a.svc.BuildHostSnapshots(c.Request.Context(), id)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

type trustReviewBody struct {
	BatchID    uint64 `json:"batch_id"`
	ReviewNote string `json:"review_note"`
}

func (a *API) trustHostApprove(c *gin.Context) {
	a.trustHostReview(c, true)
}

func (a *API) trustHostReject(c *gin.Context) {
	a.trustHostReview(c, false)
}

func (a *API) trustHostReview(c *gin.Context, approve bool) {
	id, ok := pathID(c, "id")
	if !ok {
		return
	}
	var body trustReviewBody
	if err := c.BindJSON(&body); err != nil || body.BatchID == 0 {
		dto.Fail(c, http.StatusBadRequest, "batch_id 字段是必填项。")
		return
	}
	userID, _ := middleware.UserID(c)
	payload, err := a.svc.ReviewHostCandidates(c.Request.Context(), id, body.BatchID, &userID, approve, body.ReviewNote, true)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) trustBulkApprove(c *gin.Context) {
	var body struct {
		BatchID    uint64   `json:"batch_id"`
		HostIDs    []uint64 `json:"host_ids"`
		DomainIDs  []uint64 `json:"domain_ids"`
		ReviewNote string   `json:"review_note"`
	}
	if err := c.BindJSON(&body); err != nil || body.BatchID == 0 {
		dto.Fail(c, http.StatusBadRequest, "batch_id 字段是必填项。")
		return
	}
	userID, _ := middleware.UserID(c)
	payload, err := a.svc.BulkReviewHostCandidates(c.Request.Context(), body.BatchID, &userID, true, body.ReviewNote, body.HostIDs, body.DomainIDs)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) trustImportManifest(c *gin.Context) {
	var body struct {
		ManifestText string `json:"manifest_text"`
		Format       string `json:"format"`
		SourceLabel  string `json:"source_label"`
	}
	if err := c.BindJSON(&body); err != nil {
		dto.Fail(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	userID, _ := middleware.UserID(c)
	payload, err := a.svc.ImportTrustManifest(c.Request.Context(), body.ManifestText, body.Format, body.SourceLabel, &userID)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) trustDiscoverCandidates(c *gin.Context) {
	var body struct {
		Environment string   `json:"environment"`
		DomainIDs   []uint64 `json:"domain_ids"`
		HostIDs     []uint64 `json:"host_ids"`
		Resolver    string   `json:"resolver"`
		Timeout     float64  `json:"timeout"`
		SourceLabel string   `json:"source_label"`
	}
	if err := c.BindJSON(&body); err != nil {
		dto.Fail(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if body.Environment == "" {
		body.Environment = model.TrustEnvProd
	}
	userID, _ := middleware.UserID(c)
	payload, err := a.svc.DiscoverCandidates(c.Request.Context(), body.Environment, body.DomainIDs, body.HostIDs, body.Resolver, body.Timeout, body.SourceLabel, &userID)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) trustListBuildJobs(c *gin.Context) {
	payload, err := a.svc.ListTrustBuildJobs(c.Request.Context(),
		c.Query("environment"), c.Query("status"),
		queryInt(c, "page", 1), queryInt(c, "page_size", 20))
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) trustCreateBuildJob(c *gin.Context) {
	var body struct {
		InputPath         string  `json:"input_path"`
		Environment       string  `json:"environment"`
		Limit             int     `json:"limit"`
		ChunkSize         int     `json:"chunk_size"`
		MaxHostsPerDomain int     `json:"max_hosts_per_domain"`
		Resolver          string  `json:"resolver"`
		Timeout           float64 `json:"timeout"`
		SourceLabel       string  `json:"source_label"`
		ImportOnly        bool    `json:"import_only"`
		AutoApprove       bool    `json:"auto_approve"`
	}
	if err := c.BindJSON(&body); err != nil {
		dto.Fail(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	if body.Environment == "" {
		body.Environment = model.TrustEnvProd
	}
	if body.Timeout <= 0 {
		body.Timeout = 2
	}
	userID, _ := middleware.UserID(c)
	job, err := a.svc.CreateTrustBuildJob(c.Request.Context(), body.InputPath, body.Environment,
		body.Limit, body.ChunkSize, body.MaxHostsPerDomain, body.Resolver, body.Timeout,
		body.SourceLabel, body.ImportOnly, body.AutoApprove, &userID)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, a.svc.TrustBuildJobPayload(*job))
}

func (a *API) trustBuildJobDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "构建任务不存在")
		return
	}
	job, err2 := a.svc.GetTrustBuildJob(c.Request.Context(), id)
	if err2 != nil {
		dto.Abort(c, err2)
		return
	}
	dto.OK(c, a.svc.TrustBuildJobPayload(*job))
}

func (a *API) trustBuildJobRetry(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "构建任务不存在")
		return
	}
	userID, _ := middleware.UserID(c)
	job, err2 := a.svc.RetryTrustBuildJob(c.Request.Context(), id, &userID)
	if err2 != nil {
		dto.Abort(c, err2)
		return
	}
	dto.OK(c, a.svc.TrustBuildJobPayload(*job))
}

var _ = json.Marshal

func stringsLower(v string) string {
	out := []byte(v)
	for i, ch := range out {
		if ch >= 'A' && ch <= 'Z' {
			out[i] = ch + 32
		}
	}
	return string(out)
}
