package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"dnsss/internal/auth"
	"dnsss/internal/dto"
	"dnsss/internal/middleware"
	"dnsss/internal/model"
)

func marshalJSONString(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(data)
}

type taskModel = model.Task
type executionModel = model.Execution

func checkPassword(hash, plain string) bool {
	return auth.CheckPassword(hash, plain)
}

func (a *API) latestExecution(c *gin.Context, taskID uint64) *model.Execution {
	var execution model.Execution
	if err := a.db.WithContext(c.Request.Context()).
		Where("task_id = ?", taskID).Order("id DESC").First(&execution).Error; err != nil {
		return nil
	}
	return &execution
}

func (a *API) findTask(c *gin.Context) (*model.Task, error) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		dto.Fail(c, http.StatusBadRequest, "任务不存在")
		return nil, err
	}
	var task model.Task
	if err := a.db.WithContext(c.Request.Context()).First(&task, id).Error; err != nil {
		dto.Fail(c, http.StatusBadRequest, "任务不存在")
		return nil, err
	}
	return &task, nil
}

// canReadTask 镜像原 ensure_task_access:定时任务要求属主,读路径 once 任务匿名可见。
func (a *API) canReadTask(c *gin.Context, task *model.Task) bool {
	if task.Mode == model.TaskModeSchedule {
		return a.requireOwner(c, task)
	}
	return true
}

// canMutateTask 任何修改都要求登录且属主。
func (a *API) canMutateTask(c *gin.Context, task *model.Task) bool {
	userID, authenticated := middleware.UserID(c)
	if !authenticated {
		dto.Fail(c, http.StatusForbidden, dto.ErrLoginRequired.Error())
		return false
	}
	if task.CreatedByID != nil && *task.CreatedByID != userID {
		dto.Fail(c, http.StatusForbidden, "无权访问该任务")
		return false
	}
	return true
}

func (a *API) requireOwner(c *gin.Context, task *model.Task) bool {
	userID, authenticated := middleware.UserID(c)
	if !authenticated {
		dto.Fail(c, http.StatusForbidden, dto.ErrLoginRequired.Error())
		return false
	}
	if task.CreatedByID != nil && *task.CreatedByID != userID {
		dto.Fail(c, http.StatusForbidden, "无权访问该任务")
		return false
	}
	return true
}
