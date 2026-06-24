package knxgira

import (
	"fmt"
	"strconv"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"
	"zspure/utils"

	"github.com/PuerkitoBio/goquery"
)

type KnxGiraFacilityServer struct {
	Category         string                `json:"dvs_category"`
	DeviceName       string                `json:"device_name"`
	Version          string                `json:"version"`
	CveList          []string              `json:"cves"`
	Sensibility      string                `json:"base_severity"`
	CveScore         float64               `json:"cve_score"`
	ExtraInformation model.ModuleExtraInfo `json:"dvs_extra"`
}

func (k *KnxGiraFacilityServer) SetCategory(category ...string) {
	k.Category = model.Category.Server()
}

func (k *KnxGiraFacilityServer) SetDeviceName(device ...string) {
	k.DeviceName = "KNX Gira FacilityServer"
}

func (a *KnxGiraFacilityServer) Patterns() []map[string]interface{} {
	return []map[string]interface{}{
		{"result.response.body": "<title>Gira FacilityServer"},
		{"result.response.body": "<meta charset=\"iso-8859-1\">"},
	}
}

func (k *KnxGiraFacilityServer) Filters(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		if (strings.Contains(val.(string), "<title>Gira FacilityServer") &&
			strings.Contains(val.(string), "<meta charset=\"iso-8859-1\">")) &&
			!strings.Contains(val.(string), "0<!DOCTYPE html>") &&
			!strings.Contains(val.(string), "<p hidden>") {
			return true
		}
	}
	return false
}

func (k *KnxGiraFacilityServer) DeviceScan(banner map[string]interface{}) bool {
	if banner["response"] == nil {
		return false
	}
	k.ExtraInformation.NewExtraInfo()
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if server, sok := val.(map[string]interface{})["server"].([]any); sok {
			k.ExtraInformation.SetExtraInfo("server", server[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["headers"]; ok {
		if pl, pok := val.(map[string]interface{})["x_powered_by"].([]any); pok {
			k.ExtraInformation.SetExtraInfo("programming_language", pl[0].(string))
		}
	}
	if val, ok := banner["response"].(map[string]interface{})["body"]; ok {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(val.(string)))
		if err != nil {
			return false
		}

		// Find the `TAG:div CLASS:left` and get its text it will include version
		text := doc.Find("div.left").Text()

		if text != "" {
			k.Version = text
			return true
		}
	}
	return false
}

func (k *KnxGiraFacilityServer) CveScan(els *handler.Elastic) {
	var CVE []model.CVEStructure = make([]model.CVEStructure, 0)
	var totalScore float64 = 0

	if config.LOGIC == "execute" {
		result := utils.RemoveDuplicatesFromMap(els.GatherAllDataInMap(els.CveIndex, "and", map[string]interface{}{"cve.descriptions.value": fmt.Sprintf("%s %s", k.DeviceName, k.Version)}))
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
		url := fmt.Sprintf(model.CVE.MainResource(), "knx"+"%20"+"gira"+"%20"+k.Version)
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
		k.CveList = append(k.CveList, v.CVEID)
		totalScore += v.BaseScore
	}

	k.CveScore, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", totalScore/float64(len(CVE))), 64)
	if k.CveScore > 7 {
		k.Sensibility = "HIGH"
	} else if k.CveScore >= 4 && k.CveScore <= 7 {
		k.Sensibility = "MEDIUM"
	} else if k.CveScore < 4 {
		k.Sensibility = "LOW"
	}
	k.CveList = utils.RemoveDuplicates(k.CveList)
}

func (k *KnxGiraFacilityServer) PrintInfo() string {
	return model.Category.Server() + " | KNX Gira FacilityServer"
}

func (k *KnxGiraFacilityServer) Result() model.ModuleStructure {
	return model.ModuleStructure{
		Category:         k.Category,
		DeviceName:       k.DeviceName,
		Version:          k.Version,
		CveList:          k.CveList,
		Sensibility:      k.Sensibility,
		CveScore:         k.CveScore,
		ExtraInformation: k.ExtraInformation,
	}
}
