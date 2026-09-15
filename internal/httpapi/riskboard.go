package httpapi

import (
	"github.com/gin-gonic/gin"

	"dnsss/internal/dto"
	"dnsss/internal/service"
)

func (a *API) registerRiskBoardRoutes(g *gin.RouterGroup) {
	g.GET("/risk-board/meta", a.riskBoardMeta)
	g.GET("/risk-board/overview", a.riskBoardOverview)
	g.GET("/risk-board/globe-layers", a.riskBoardGlobeLayers)
	g.GET("/risk-board/node-distribution", a.riskBoardNodeDistribution)
	g.GET("/risk-board/batch-risk-overview", a.riskBoardBatchRiskOverview)
	g.GET("/passive-alerts/overview", a.passiveAlertsOverview)
}

func (a *API) riskBoardMeta(c *gin.Context) {
	payload, err := a.svc.BuildRiskBoardMeta(c.Request.Context())
	if err != nil {
		dto.Abort(c, err)
		return
	}
	dto.OK(c, payload)
}

func (a *API) riskBoardOverview(c *gin.Context) {
	dto.OK(c, a.svc.BuildRiskBoardOverview(c.Request.Context(),
		c.DefaultQuery("window", "24h"), c.DefaultQuery("protocol", "all"), c.DefaultQuery("environment", "prod")))
}

func (a *API) riskBoardGlobeLayers(c *gin.Context) {
	dto.OK(c, a.svc.BuildGlobeLayers(c.Request.Context(),
		c.DefaultQuery("window", "24h"), c.DefaultQuery("environment", "prod")))
}

func (a *API) riskBoardNodeDistribution(c *gin.Context) {
	dto.OK(c, a.svc.BuildNodeDistribution(c.Request.Context(),
		c.DefaultQuery("window", "24h"), c.DefaultQuery("protocol", "all"), c.DefaultQuery("environment", "prod")))
}

func (a *API) riskBoardBatchRiskOverview(c *gin.Context) {
	dto.OK(c, a.svc.BuildBatchRiskOverview(c.Request.Context(),
		c.DefaultQuery("window", "24h"), c.DefaultQuery("protocol", "all"), c.DefaultQuery("environment", "prod")))
}

func (a *API) passiveAlertsOverview(c *gin.Context) {
	dto.OK(c, service.BuildPassiveAlertsOverview(service.PassiveAlertsFilters{
		Window:    c.DefaultQuery("window", "24h"),
		Start:     c.Query("start"),
		End:       c.Query("end"),
		AlertType: c.Query("alert_type"),
		Keyword:   c.Query("keyword"),
		Page:      queryInt(c, "page", 1),
		Size:      queryInt(c, "size", 20),
		Preset:    c.Query("preset"),
	}))
}
