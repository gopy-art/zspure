package wirelessrouter

import (
	"strings"
	"zspure/handler"
	"zspure/modules/model"
)

type WirelessRouterPanel struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (w *WirelessRouterPanel) SetCategory(category ...string) {
	w.Category = model.Category.Router()
}

func (w *WirelessRouterPanel) SetDeviceName(device ...string) {
	w.DeviceName = "Wireless Router Panel"
}

func (a *WirelessRouterPanel) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title>Router</title>"},
		{"result.response.body": "<body class=\"gui_title\">"},
	}
}

func (w *WirelessRouterPanel) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if strings.Contains(val.(string), "<title>Router</title>") &&
			strings.Contains(val.(string), "<body class=\"gui_title\">") &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (w *WirelessRouterPanel) DeviceScan(banner map[string]interface{}) bool {
	w.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			w.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			w.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	return false
}

func (w *WirelessRouterPanel) CveScan(els *handler.Elastic) {}

func (w *WirelessRouterPanel) PrintInfo() string {
	return model.Category.Router() + " | Wireless Router Panel"
}

func (w *WirelessRouterPanel) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         w.Category,
		DeviceName:       w.DeviceName,
		Version:          w.Version,
		CveList:          w.CveList,
		Sensibility:      w.Sensibility,
		CveScore:         w.CveScore,
		ExtraInformation: w.ExtraInformation,
	}
}
