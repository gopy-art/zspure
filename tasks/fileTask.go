package tasks

import (
	"slices"
	"sync"
	"zspure/config"
	"zspure/modules"
	"zspure/modules/model"
	"zspure/utils"
)

func DetectDeviceBaseFile(content string) error {
	var wg sync.WaitGroup
	m := model.GatherModuleSructure{
		Protocol: "http",
		Banner: map[string]any{
			"response": map[string]any{
				"body": content,
				"headers": map[string]any{
					"server":       []string{""},
					"x_powered_by": []string{""},
				},
			},
		},
	}

	handlers, err := modules.NewModule(m.Protocol)
	if err != nil {
		return err
	} else {
		for method10 := range slices.Chunk(handlers, 10) {
			for _, method := range method10 {
				wg.Go(func() {
					if res := method.Filters(m.Banner); res {
						method.SetCategory()
						method.SetDeviceName()
						method.DeviceScan(m.Banner)
						if config.FIND_CVE {
							method.CveScan(nil)
						}

						utils.NormalizeOutput(method.Result())
					}
				})
			}
			wg.Wait()
		}
	}
	
	return nil
}

func DetectDeviceBaseURL(content string, headers map[string]interface{}) error {
	var wg sync.WaitGroup
	var xPowered, server string
	if val, ok := headers["x-powered-by"].(string); ok {
		xPowered = val
	}
	if val, ok := headers["server"].(string); ok {
		server = val
	}

	m := model.GatherModuleSructure{
		Protocol: "http",
		Banner: map[string]any{
			"response": map[string]any{
				"body": content,
				"headers": map[string]any{
					"server":       []string{server},
					"x_powered_by": []string{xPowered},
				},
			},
		},
	}

	handlers, err := modules.NewModule(m.Protocol)
	if err != nil {
		return err
	} else {
		for method10 := range slices.Chunk(handlers, 10) {
			for _, method := range method10 {
				wg.Go(func() {
					if res := method.Filters(m.Banner); res {
						method.SetCategory()
						method.SetDeviceName()
						method.DeviceScan(m.Banner)
						if config.FIND_CVE {
							method.CveScan(nil)
						}

						utils.NormalizeOutput(method.Result())
					}
				})
			}
			wg.Wait()
		}
	}
	
	return nil
}
