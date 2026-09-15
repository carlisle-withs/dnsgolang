// Package httpapi 路由注册(对照原系统 urls.py 的 52 接口契约;本阶段交付
// 认证 + meta + 单目标拨测全链路,批量/大屏/可信库按 Phase 4-7 迭代)。
package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"dnsss/internal/auth"
	"dnsss/internal/config"
	"dnsss/internal/dto"
	"dnsss/internal/middleware"
	"dnsss/internal/model"
	"dnsss/internal/queue"
	"dnsss/internal/service"
)

type API struct {
	cfg   *config.Config
	db    *gorm.DB
	jwt   *auth.Manager
	svc   *service.Service
	queue *queue.Client // 配置了 Redis 时经 Asynq 派发,否则进程内执行
}

func New(cfg *config.Config, db *gorm.DB, jwt *auth.Manager, svc *service.Service, q *queue.Client) *API {
	return &API{cfg: cfg, db: db, jwt: jwt, svc: svc, queue: q}
}

func (a *API) Router() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(middleware.Recover(), middleware.RequestLogger(), middleware.CORS(a.cfg.CORSOrigins), middleware.JWT(a.jwt))

	r.GET("/healthz", func(c *gin.Context) {
		dto.OK(c, gin.H{"status": "ok"})
	})

	oauth := r.Group("/api/oauth")
	{
		oauth.POST("/login/", a.oauthLogin)
		oauth.POST("/refresh/", a.oauthRefresh)
		oauth.GET("/info/", a.oauthInfo)
	}

	netprobe := r.Group("/api/netprobe")
	{
		netprobe.GET("/meta", a.meta)
		netprobe.GET("/tasks", a.listTasks)
		netprobe.POST("/tasks", a.createTask)
		netprobe.GET("/tasks/:id", a.getTask)
		netprobe.PUT("/tasks/:id", a.updateTask)
		netprobe.PATCH("/tasks/:id", a.updateTask)
		netprobe.DELETE("/tasks/:id", a.deleteTask)
		netprobe.GET("/tasks/:id/executions", a.taskExecutions)
		netprobe.GET("/executions/:id", a.executionDetail)
		a.registerBatchRoutes(netprobe)
		a.registerRiskBoardRoutes(netprobe)
	}
	a.registerTrustRoutes(r)
	return r
}

// ---------- oauth ----------

func (a *API) oauthLogin(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&body); err != nil {
		dto.Fail(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	var user struct {
		ID           uint64
		Username     string
		PasswordHash string
		IsActive     bool
	}
	err := a.db.Where("username = ?", body.Username).Table("users").
		Select("id, username, password_hash, is_active").Scan(&user).Error
	if err != nil || user.ID == 0 {
		dto.Fail(c, http.StatusBadRequest, "用户名或密码错误")
		return
	}
	if !user.IsActive || !checkPassword(user.PasswordHash, body.Password) {
		dto.Fail(c, http.StatusBadRequest, "用户名或密码错误")
		return
	}
	token, err := a.jwt.Issue(user.ID, user.Username)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, gin.H{"token": token})
}

func (a *API) oauthRefresh(c *gin.Context) {
	var body struct {
		Token string `json:"token"`
	}
	if err := c.BindJSON(&body); err != nil || body.Token == "" {
		dto.Fail(c, http.StatusBadRequest, "token 字段是必填项。")
		return
	}
	token, err := a.jwt.Refresh(body.Token)
	if err != nil {
		dto.Fail(c, http.StatusForbidden, "token 已过期或无效")
		return
	}
	dto.OK(c, gin.H{"token": token})
}

func (a *API) oauthInfo(c *gin.Context) {
	userID, ok := middleware.UserID(c)
	if !ok {
		dto.Fail(c, http.StatusForbidden, dto.ErrLoginRequired.Error())
		return
	}
	var user struct {
		ID       uint64
		Username string
		Name     string
		Email    string
		Avatar   string
		Mobile   *string
	}
	if err := a.db.Table("users").Select("id, username, name, email, avatar, mobile").
		Where("id = ?", userID).Scan(&user).Error; err != nil || user.ID == 0 {
		dto.Fail(c, http.StatusForbidden, dto.ErrLoginRequired.Error())
		return
	}
	mobile := ""
	if user.Mobile != nil {
		mobile = *user.Mobile
	}
	avatar := user.Avatar
	if avatar == "" {
		avatar = "/media/avatar/default.png"
	}
	dto.OK(c, gin.H{
		"id": user.ID, "username": user.Username, "name": user.Name,
		"avatar": avatar, "email": user.Email,
		"permissions": []string{"*"},
		"department": "", "mobile": mobile,
	})
}

// ---------- netprobe meta ----------

func (a *API) meta(c *gin.Context) {
	payload, err := a.svc.BuildMeta(c.Request.Context())
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

// dispatchSingle 单次拨测派发:优先 Asynq(default 队列),否则进程内。
func (a *API) dispatchSingle(executionID uint64) {
	if a.queue != nil {
		if _, err := a.queue.EnqueueDispatchExecution(executionID, model.TriggerManual); err == nil {
			return
		}
	}
	a.svc.DispatchExecution(executionID, model.TriggerManual)
}

// ---------- netprobe tasks ----------

func (a *API) listTasks(c *gin.Context) {
	userID, authenticated := middleware.UserID(c)
	if !authenticated {
		dto.Fail(c, http.StatusForbidden, "请先登录后查看监控任务")
		return
	}
	mode := c.Query("mode")
	protocol := c.Query("protocol")

	query := a.db.Model(&model.Task{}).Where("created_by_id = ?", userID)
	if mode != "" {
		query = query.Where("mode = ?", mode)
	}
	if protocol != "" {
		query = query.Where("protocol = ?", protocol)
	}
	var total int64
	query.Count(&total)
	var tasks []model.Task
	query.Order("id DESC").Limit(100).Find(&tasks)

	results := make([]map[string]any, 0, len(tasks))
	for i := range tasks {
		latest := a.latestExecution(c, tasks[i].ID)
		results = append(results, a.svc.BuildTaskPayload(c.Request.Context(), &tasks[i], latest))
	}
	dto.OK(c, gin.H{"results": results, "total": total})
}

func (a *API) createTask(c *gin.Context) {
	var body struct {
		Mode          string         `json:"mode"`
		Protocol      string         `json:"protocol"`
		Target        string         `json:"target"`
		TargetDisplay string         `json:"targetDisplay"`
		Regions       []string       `json:"regions"`
		Options       map[string]any `json:"options"`
		Schedule      string         `json:"schedule"`
	}
	if err := c.BindJSON(&body); err != nil {
		dto.Fail(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	userID, authenticated := middleware.UserID(c)
	task, execution, err := a.svc.CreateTask(c.Request.Context(), service.CreateTaskInput{
		Mode: body.Mode, Protocol: body.Protocol, Target: body.Target,
		TargetDisplay: body.TargetDisplay, Regions: body.Regions,
		Options: body.Options, Schedule: body.Schedule,
	}, userID, authenticated, c.ClientIP())
	if err != nil {
		dto.Abort(c, err)
		return
	}
	if task.Mode == "schedule" {
		dto.Created(c, a.svc.BuildTaskPayload(c.Request.Context(), task, nil))
		return
	}
	a.dispatchSingle(execution.ID)
	payload := a.svc.BuildTaskPayload(c.Request.Context(), task, execution)
	payload["latestExecution"] = gin.H{
		"id": execution.ID, "executionNo": execution.ExecutionNo, "status": execution.Status,
	}
	payload["resultUrl"] = "/network-probe/result/" + strconv.FormatUint(execution.ID, 10)
	dto.Created(c, payload)
}

func (a *API) getTask(c *gin.Context) {
	task, err := a.findTask(c)
	if err != nil {
		return
	}
	if !a.canReadTask(c, task) {
		return
	}
	dto.OK(c, a.svc.BuildTaskPayload(c.Request.Context(), task, a.latestExecution(c, task.ID)))
}

func (a *API) updateTask(c *gin.Context) {
	task, err := a.findTask(c)
	if err != nil {
		return
	}
	if !a.canMutateTask(c, task) {
		return
	}
	if task.Mode != "schedule" {
		dto.Fail(c, http.StatusBadRequest, "仅定时任务支持编辑")
		return
	}
	var body struct {
		Target    *string        `json:"target"`
		Regions   []string       `json:"regions"`
		Options   map[string]any `json:"options"`
		Schedule  *string        `json:"schedule"`
		IsEnabled *bool          `json:"isEnabled"`
	}
	if err := c.BindJSON(&body); err != nil {
		dto.Fail(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	updates := map[string]any{}
	if body.Target != nil && *body.Target != "" {
		updates["target"] = *body.Target
		updates["target_display"] = *body.Target
	}
	if body.Schedule != nil && *body.Schedule != "" {
		updates["schedule_cron"] = *body.Schedule
	}
	if len(body.Regions) > 0 {
		normalized, err := a.svc.NormalizeRegionCodes(c.Request.Context(), body.Regions)
		if err != nil {
			dto.Abort(c, err)
			return
		}
		updates["region_codes_text"] = marshalJSONString(normalized)
	}
	if body.Options != nil {
		var merged map[string]any
		_ = json.Unmarshal([]byte(task.OptionsTx), &merged)
		if merged == nil {
			merged = map[string]any{}
		}
		for k, v := range body.Options {
			merged[k] = v
		}
		updates["options_text"] = marshalJSONString(merged)
	}
	if body.IsEnabled != nil {
		updates["is_enabled"] = *body.IsEnabled
		if *body.IsEnabled {
			updates["status"] = "pending"
		} else {
			updates["status"] = "disabled"
		}
	}
	if err := a.db.Model(task).Updates(updates).Error; err != nil {
		dto.Abort(c, err)
		return
	}
	a.db.First(task, task.ID)
	dto.OK(c, a.svc.BuildTaskPayload(c.Request.Context(), task, a.latestExecution(c, task.ID)))
}

func (a *API) deleteTask(c *gin.Context) {
	task, err := a.findTask(c)
	if err != nil {
		return
	}
	if !a.canMutateTask(c, task) {
		return
	}
	if err := a.db.Delete(task).Error; err != nil {
		dto.Abort(c, err)
		return
	}
	dto.NoContent(c)
}

func (a *API) taskExecutions(c *gin.Context) {
	task, err := a.findTask(c)
	if err != nil {
		return
	}
	if !a.canReadTask(c, task) {
		return
	}
	var executions []executionModel
	a.db.Where("task_id = ?", task.ID).Order("id DESC").Limit(50).Find(&executions)
	results := make([]map[string]any, 0, len(executions))
	for i := range executions {
		results = append(results, map[string]any{
			"id": executions[i].ID,
			"executionNo": executions[i].ExecutionNo,
			"status": executions[i].Status,
			"triggerType": executions[i].TriggerType,
			"startedAt": executions[i].StartedAt,
			"finishedAt": executions[i].FinishedAt,
			"successRegionCount": executions[i].SuccessRegionCount,
			"totalRegionCount": executions[i].TotalRegionCount,
			"availabilityRatio": executions[i].AvailabilityRatio,
			"summaryMessage": executions[i].SummaryMessage,
		})
	}
	dto.OK(c, gin.H{"results": results})
}

func (a *API) executionDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "执行记录不存在")
		return
	}
	payload, err := a.svc.BuildExecutionPayload(c.Request.Context(), id)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "执行记录不存在")
		return
	}
	dto.OK(c, payload)
}
