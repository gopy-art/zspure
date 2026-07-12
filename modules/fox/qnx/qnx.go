package qnx

import (
	"fmt"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type FoxQnx struct {
	Category    string                `json:"dvs_category"`
	DeviceName  string                `json:"device_name"`
	Version     string                `json:"version"`
	CveList     []string              `json:"cves"`
	Sensibility string                `json:"base_severity"`
	CveScore    float64               `json:"cve_score"`
	ExtraInfo   model.ModuleExtraInfo `json:"dvs_extra"`
}

var modelType string

var vendors = map[string][]string{
	"vykon":        {"Vykon", "scada controller"},
	"facexp":       {"FacExp", "scada controller"},
	"websopen":     {"Honeywell", "scada controller"},
	"webs":         {"Honeywell", "scada controller"},
	"distech":      {"Distech Controls", "scada controller"},
	"centraline":   {"Honeywell", "scada controller"},
	"staefa":       {"Siemens", "scada controller"},
	"tac":          {"Schneider Electric", "scada controller"},
	"webeasy":      {"Webeasy", "scada controller"},
	"alerton":      {"Alerton", "hvac"},
	"nexrev":       {"NexRev", "hvac"},
	"comfortpoint": {"Honeywell", "scada controller"},
	"novar.opus":   {"Novar", " Typehvac"},
	"trend":        {"Trend", "scada controller"},
	"tridium":      {"Tridium", "scada controller"},
	"bactalk":      {"Alerton", "scada controller"},
	"webvision":    {"Honeywell", "hvac"},
	"trane":        {"Trane", "hvac"},
	"integra":      {"Integra", "CINEMA"},
	"wattstopper":  {"WATTSTOPPER", "light controller"},
	"vyko":         {"Vykon", "scada controller"},
	"eiq":          {"eIQ", "solar panel"},
	"thinksimple":  {"Think Simple", "scada controller"},
}

func (f *FoxQnx) SetCategory(category ...string) {
	f.Category = model.Category.Controller()
}

func (f *FoxQnx) SetDeviceName(device ...string) {
	f.DeviceName = "fox"
}

func (f *FoxQnx) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (f *FoxQnx) Filters(banner map[string]interface{}) bool {
	if banner["is_fox"] == nil || banner["version"] == nil {
		return false
	}
	if val, ok := banner["is_fox"].(bool); ok && val {
		if val2, ok := banner["os_name"]; ok {
			versionStr := fmt.Sprintf("%v", val2)
			if strings.Contains(versionStr, "QNX") {
				return true
			}
		}
	}
	return false
}

func (f *FoxQnx) DeviceScan(banner map[string]interface{}) bool {
	if banner["is_fox"] == nil || banner["version"] == nil {
		return false
	}
	f.ExtraInfo.NewExtraInfo()
	if val, ok := banner["station_name"].(string); ok && val != "" {
		f.ExtraInfo.SetExtraInfo("station_name", val)

	}
	if val, ok := banner["version"].(string); ok && val != "" {
		f.ExtraInfo.SetExtraInfo("version", val)
	}
	if val, ok := banner["vm_name"].(string); ok && val != "" {
		f.ExtraInfo.SetExtraInfo("vm_name", val)
	}
	if val, ok := banner["app_name"].(string); ok && val != "" {
		f.ExtraInfo.SetExtraInfo("app_name", val)
	}
	if val, ok := banner["host_id"].(string); ok && val != "" {
		f.ExtraInfo.SetExtraInfo("host_id", val)
	}
	if val, ok := banner["hostname"].(string); ok && val != "" {
		f.ExtraInfo.SetExtraInfo("hostname", val)
	}
	if val, ok := banner["brand_id"].(string); ok && val != "" {
		if v, ok := vendors[strings.ToLower(val)]; ok {
			f.ExtraInfo.SetExtraInfo("manufacturer", v[0])
			// f.ExtraInfo.SetExtraInfo("device_type", v[1])
			modelType = v[1]
		}
	}
	if val, ok := banner["os_name"].(string); ok && val != "" {
		f.ExtraInfo.SetExtraInfo("os_name", val)
		if strings.Contains(val, "QNX") {
			return true
		}
	}

	return false
}

func (f *FoxQnx) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": modelType,
		}))
		if len(result) == 0 {
			return
		}
		for _, c := range result {
			if len(CVE) == 10 {
				break
			}
			cveMod := model.NewCVEStructure(c)
			CVE = append(CVE, cveMod)
		}
	} else if config.FIND_CVE {
		url := fmt.Sprintf(model.CVE.MainResource(), modelType)
		recieve, err := utils.GatherCVEOnline(url)
		if err != nil {
			fmt.Println("[CVE] error in gather the CVE for this device. (Server error)")
			return
		}
		CVE = append(CVE, recieve...)
	}

	if len(CVE) == 0 {
		cmd.InfoLogger.Println("[CVE] do not find any CVE for this module.")
		return
	}

	for _, vl := range CVE {
		f.CveList = append(f.CveList, vl.CVEID)
		totalScore += vl.BaseScore
	}

	f.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if f.CveScore > 7 {
		f.Sensibility = "HIGH"
	} else if f.CveScore >= 4 && f.CveScore <= 7 {
		f.Sensibility = "MEDIUM"
	} else if f.CveScore < 4 {
		f.Sensibility = "LOW"
	}
	f.CveList = utils.RemoveDuplicates(f.CveList)
}

func (f *FoxQnx) PrintInfo() string { return model.Category.Controller() + " | Fox Devices" }

func (f *FoxQnx) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         f.Category,
		DeviceName:       f.DeviceName,
		Version:          f.Version,
		CveList:          f.CveList,
		Sensibility:      f.Sensibility,
		CveScore:         f.CveScore,
		ExtraInformation: f.ExtraInfo,
	}
}
