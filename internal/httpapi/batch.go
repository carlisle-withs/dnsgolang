package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"dnsss/internal/dto"
	"dnsss/internal/middleware"
	"dnsss/internal/model"
	"dnsss/internal/service"
)

func (a *API) registerBatchRoutes(g *gin.RouterGroup) {
	g.GET("/batch/tasks", a.listBatchTasks)
	g.POST("/batch/tasks", a.createBatchTask)
	g.GET("/batch/tasks/:id", a.getBatchTask)
	g.PATCH("/batch/tasks/:id", a.updateBatchTask)
	g.PUT("/batch/tasks/:id", a.updateBatchTask)
	g.DELETE("/batch/tasks/:id", a.deleteBatchTask)
	g.POST("/batch/tasks/:id/rerun", a.rerunBatchTask)
	g.GET("/batch/tasks/:id/executions", a.batchTaskExecutions)
	g.GET("/batch/executions/:id", a.batchExecutionDetail)
	g.POST("/batch/executions/:id/stop", a.stopBatchExecution)
	g.GET("/batch/executions/:id/results", a.batchExecutionResults)
	g.GET("/batch/results/:id", a.batchResultDetail)
}

// createBatchTask 对应原 BatchTaskCreateAPIView(multipart/form-data)。
func (a *API) createBatchTask(c *gin.Context) {
	userID, authenticated := middleware.UserID(c)
	if !authenticated {
		dto.Fail(c, http.StatusForbidden, dto.ErrLoginRequired.Error())
		return
	}
	// gin 在 Bind 未触发时不会解析 form;这里主动解析 multipart 与 urlencoded 两种形态
	_ = c.Request.ParseMultipartForm(8 << 20)
	if err := c.Request.ParseForm(); err != nil {
		dto.Fail(c, http.StatusBadRequest, "请求体必须是 multipart/form-data 或 form")
		return
	}
	input := service.CreateBatchInput{
		Protocol:    formValue(c, "protocol"),
		InputMode:   formValue(c, "input_mode"),
		TargetsText: formValue(c, "targets_text"),
		Mode:        formValue(c, "mode"),
		Schedule:    formValue(c, "schedule"),
		Regions:     formValues(c, "regions"),
	}
	if rawOptions := formValue(c, "options"); rawOptions != "" {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(rawOptions), &parsed); err != nil {
			dto.Fail(c, http.StatusBadRequest, "options 必须是合法 JSON")
			return
		}
		input.Options = parsed
	}
	if input.InputMode == "file" {
		file, header, err := c.Request.FormFile("file")
		if err != nil {
			dto.Fail(c, http.StatusBadRequest, "请上传 txt/csv 文件")
			return
		}
		defer file.Close()
		buf := make([]byte, 2*1024*1024+1)
		n, _ := file.Read(buf)
		input.FileName = header.Filename
		input.FileContent = buf[:n]
	}
	task, execution, err := a.svc.CreateBatchTask(c.Request.Context(), input, userID, c.ClientIP())
	if err != nil {
		dto.Abort(c, err)
		return
	}
	if task.Mode == model.TaskModeSchedule {
		dto.Created(c, a.svc.BuildBatchTaskPayload(c.Request.Context(), task))
		return
	}
	workerTaskID := a.dispatchBatch(execution.ID, model.TriggerManual)
	if workerTaskID != "" {
		a.db.Model(execution).Update("worker_task_id", workerTaskID)
		execution.WorkerTaskID = workerTaskID
	}
	dto.Created(c, gin.H{
		"taskId":     task.ID,
		"executionId": execution.ID,
		"task":       a.svc.BuildBatchTaskPayload(c.Request.Context(), task),
		"execution":  a.svc.BuildBatchExecutionSummary(c.Request.Context(), execution, task),
		"inputStats": gin.H{
			"totalInputCount":   task.TotalInputCount,
			"validTargetCount":  task.ValidTargetCount,
			"invalidTargetCount": task.InvalidTargetCount,
			"duplicateCount":    task.DuplicateCount,
		},
		"resultUrl": "/network-probe/batch-result/" + strconv.FormatUint(execution.ID, 10),
	})
}

// dispatchBatch 批量执行入队:配置了 Redis 走 Asynq,否则进程内执行(开发形态)。
func (a *API) dispatchBatch(executionID uint64, triggerType string) string {
	if a.queue != nil {
		if id, err := a.queue.EnqueueDispatchBatchExecution(executionID, triggerType); err == nil {
			return id
		}
	}
	a.svc.DispatchBatchInProcess(executionID, triggerType)
	return ""
}

func formValue(c *gin.Context, key string) string {
	if v := c.PostForm(key); v != "" {
		return v
	}
	return c.Query(key)
}

func formValues(c *gin.Context, key string) []string {
	values, ok := c.Request.Form[key]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (a *API) listBatchTasks(c *gin.Context) {
	userID, authenticated := middleware.UserID(c)
	if !authenticated {
		dto.Fail(c, http.StatusForbidden, dto.ErrLoginRequired.Error())
		return
	}
	page := queryInt(c, "page", 1)
	size := queryInt(c, "size", 20)
	if size < 1 || size > 100 {
		size = 20
	}
	query := a.db.Model(&model.BatchTask{}).Where("created_by_id = ?", userID)
	if mode := c.Query("mode"); mode != "" {
		query = query.Where("mode = ?", mode)
	}
	if protocol := c.Query("protocol"); protocol != "" {
		query = query.Where("protocol = ?", protocol)
	}
	var total int64
	query.Count(&total)
	var tasks []model.BatchTask
	query.Order("id DESC").Offset((page - 1) * size).Limit(size).Find(&tasks)
	results := make([]map[string]any, 0, len(tasks))
	for i := range tasks {
		results = append(results, a.svc.BuildBatchTaskPayload(c.Request.Context(), &tasks[i]))
	}
	dto.OK(c, gin.H{"results": results, "total": total})
}

func queryInt(c *gin.Context, key string, fallback int) int {
	if v := c.Query(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func (a *API) findBatchTask(c *gin.Context) (*model.BatchTask, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "批量任务不存在")
		return nil, false
	}
	var task model.BatchTask
	if err := a.db.First(&task, id).Error; err != nil {
		dto.Fail(c, http.StatusBadRequest, "批量任务不存在")
		return nil, false
	}
	userID, authenticated := middleware.UserID(c)
	if !authenticated {
		dto.Fail(c, http.StatusForbidden, dto.ErrLoginRequired.Error())
		return nil, false
	}
	if task.CreatedByID != nil && *task.CreatedByID != userID {
		dto.Fail(c, http.StatusForbidden, "无权访问该批量任务")
		return nil, false
	}
	return &task, true
}

func (a *API) getBatchTask(c *gin.Context) {
	task, ok := a.findBatchTask(c)
	if !ok {
		return
	}
	dto.OK(c, a.svc.BuildBatchTaskDetailPayload(c.Request.Context(), task))
}

// updateBatchTask 定时任务编辑(镜像 PATCH 语义的最小集:启停/调度)。
func (a *API) updateBatchTask(c *gin.Context) {
	task, ok := a.findBatchTask(c)
	if !ok {
		return
	}
	if task.Mode != model.TaskModeSchedule {
		dto.Fail(c, http.StatusBadRequest, "仅定时批量任务支持编辑")
		return
	}
	var body struct {
		Schedule  *string `json:"schedule"`
		IsEnabled *bool   `json:"isEnabled"`
	}
	if err := c.BindJSON(&body); err != nil {
		dto.Fail(c, http.StatusBadRequest, "请求体格式错误")
		return
	}
	updates := map[string]any{}
	if body.Schedule != nil && *body.Schedule != "" {
		updates["schedule_cron"] = *body.Schedule
	}
	if body.IsEnabled != nil {
		updates["is_enabled"] = *body.IsEnabled
		if *body.IsEnabled {
			updates["status"] = model.BatchStatusPending
		} else {
			updates["status"] = model.BatchStatusDisabled
		}
	}
	if len(updates) > 0 {
		a.db.Model(task).Updates(updates)
	}
	dto.OK(c, a.svc.BuildBatchTaskDetailPayload(c.Request.Context(), task))
}

func (a *API) deleteBatchTask(c *gin.Context) {
	task, ok := a.findBatchTask(c)
	if !ok {
		return
	}
	if err := a.db.Delete(task).Error; err != nil {
		dto.Abort(c, err)
		return
	}
	dto.NoContent(c)
}

func (a *API) rerunBatchTask(c *gin.Context) {
	task, ok := a.findBatchTask(c)
	if !ok {
		return
	}
	fresh, execution, err := a.svc.RerunBatchTask(c.Request.Context(), task.ID)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	workerTaskID := a.dispatchBatch(execution.ID, model.TriggerRetry)
	if workerTaskID != "" {
		a.db.Model(execution).Update("worker_task_id", workerTaskID)
		execution.WorkerTaskID = workerTaskID
	}
	dto.Created(c, gin.H{
		"taskId": fresh.ID, "executionId": execution.ID,
		"task":      a.svc.BuildBatchTaskPayload(c.Request.Context(), fresh),
		"execution": a.svc.BuildBatchExecutionSummary(c.Request.Context(), execution, fresh),
		"resultUrl": "/network-probe/batch-result/" + strconv.FormatUint(execution.ID, 10),
	})
}

func (a *API) batchTaskExecutions(c *gin.Context) {
	task, ok := a.findBatchTask(c)
	if !ok {
		return
	}
	var executions []model.BatchExecution
	a.db.Where("batch_task_id = ?", task.ID).Order("id DESC").Limit(50).Find(&executions)
	results := make([]map[string]any, 0, len(executions))
	for i := range executions {
		results = append(results, a.svc.BuildBatchExecutionSummary(c.Request.Context(), &executions[i], task))
	}
	dto.OK(c, gin.H{"results": results})
}

func (a *API) findBatchExecution(c *gin.Context) (*model.BatchExecution, *model.BatchTask, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "批量执行不存在")
		return nil, nil, false
	}
	var execution model.BatchExecution
	if err := a.db.First(&execution, id).Error; err != nil {
		dto.Fail(c, http.StatusBadRequest, "批量执行不存在")
		return nil, nil, false
	}
	var task model.BatchTask
	if err := a.db.First(&task, execution.BatchTaskID).Error; err != nil {
		dto.Fail(c, http.StatusBadRequest, "批量任务不存在")
		return nil, nil, false
	}
	userID, authenticated := middleware.UserID(c)
	if !authenticated {
		dto.Fail(c, http.StatusForbidden, dto.ErrLoginRequired.Error())
		return nil, nil, false
	}
	if task.CreatedByID != nil && *task.CreatedByID != userID {
		dto.Fail(c, http.StatusForbidden, "无权访问该批量任务")
		return nil, nil, false
	}
	return &execution, &task, true
}

func (a *API) batchExecutionDetail(c *gin.Context) {
	_, _, ok := a.findBatchExecution(c)
	if !ok {
		return
	}
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	payload, err := a.svc.BuildBatchExecutionPayload(c.Request.Context(), id)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "批量执行不存在")
		return
	}
	dto.OK(c, payload)
}

func (a *API) stopBatchExecution(c *gin.Context) {
	execution, _, ok := a.findBatchExecution(c)
	if !ok {
		return
	}
	if err := a.svc.RequestBatchStop(c.Request.Context(), execution.ID); err != nil {
		dto.Abort(c, err)
		return
	}
	id := execution.ID
	payload, err := a.svc.BuildBatchExecutionPayload(c.Request.Context(), id)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) batchExecutionResults(c *gin.Context) {
	_, _, ok := a.findBatchExecution(c)
	if !ok {
		return
	}
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	q := service.BatchResultsQuery{
		Page:       queryInt(c, "page", 1),
		Size:       queryInt(c, "size", 20),
		Status:     c.Query("status"),
		Protocol:   c.Query("protocol"),
		ResultCode: c.Query("result_code"),
		Keyword:    c.Query("keyword"),
		Sort:       c.Query("sort"),
	}
	payload, err := a.svc.BuildBatchResultsPayload(c.Request.Context(), id, q)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) batchResultDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "批量结果不存在")
		return
	}
	payload, err := a.svc.BuildBatchResultDetail(c.Request.Context(), id)
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}
