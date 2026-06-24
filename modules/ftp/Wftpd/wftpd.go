package wftpd

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"
)

type WFTPdWindowsSystems struct {
	Category    string   `json:"dvs_category"`
	DeviceName  string   `json:"device_name"`
	Version     string   `json:"version"`
	CveList     []string `json:"cves"`
	Sensibility string   `json:"base_severity"`
	CveScore    float64  `json:"cve_score"`
}

func (w *WFTPdWindowsSystems) SetCategory(category ...string) {
	w.Category = model.Category.Service()
}

func (w *WFTPdWindowsSystems) SetDeviceName(device ...string) {
	w.DeviceName = "WFTPd Windows Systems"
}

func (w *WFTPdWindowsSystems) Patterns() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (w *WFTPdWindowsSystems) Filters(banner map[string]interface{}) bool {
	if banner["banner"] != nil && banner["banner"].(string) != "" && strings.Contains(banner["banner"].(string), "WFTPD") {
		return true
	}
	return false
}

func (w *WFTPdWindowsSystems) DeviceScan(banner map[string]interface{}) bool {
	re := regexp.MustCompile(`WFTPD\s+(\d+\.\d+)`)
	matches := re.FindStringSubmatch(banner["banner"].(string))
	if len(matches) > 1 {
		w.Version = matches[1]
		return true
	}
	return false
}

func (w *WFTPdWindowsSystems) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{
			"cve.descriptions.value": fmt.Sprintf("wftpd %v", w.Version),
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
		url := fmt.Sprintf(model.CVE.MainResource(),
			strings.ToLower(strings.ReplaceAll(fmt.Sprintf("wftpd %v", w.Version), " ", "%20")))
		recieve, err := utils.GatherCVEOnline(url)
		if err != nil {
			cmd.ErrorLogger.Println("[CVE] error in gather the CVE for this device. (Server error)")
			return
		}
		CVE = append(CVE, recieve...)
	}

	if len(CVE) == 0 {
		cmd.InfoLogger.Println("[CVE] do not find any CVE for this module.")
		return
	}

	for _, v := range CVE {
		w.CveList = append(w.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	w.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if w.CveScore > 7 {
		w.Sensibility = "HIGH"
	} else if w.CveScore >= 4 && w.CveScore <= 7 {
		w.Sensibility = "MEDIUM"
	} else if w.CveScore < 4 {
		w.Sensibility = "LOW"
	}
	w.CveList = utils.RemoveDuplicates(w.CveList)
}

func (w *WFTPdWindowsSystems) PrintInfo() string {
	return model.Category.Service() + " | WFTPd Windows Systems"
}

func (w *WFTPdWindowsSystems) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:    w.Category,
		DeviceName:  w.DeviceName,
		Version:     w.Version,
		CveList:     w.CveList,
		Sensibility: w.Sensibility,
		CveScore:    w.CveScore,
	}
}
