package tasks

import (
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/modules"
	"zspure/modules/model"
)

func DetectDeviceBaseFile(content string) (error) {
	var wg sync.WaitGroup
	m := model.GatherModuleSructure{
		Protocol: "http",
		Banner: map[string]any{
			"response": map[string]any{
				"body": content,
			},
		},
	}

	handlers, err := modules.NewModule(m.Protocol)
	if err != nil {
		return err
	} else {
		for method10 := range slices.Chunk(handlers, 10) {
			for _, method := range method10 {				
				wg.Go(func(){
					if res := method.Filters(m.Banner); res {
						method.SetCategory()
						method.SetDeviceName()
						method.DeviceScan(m.Banner)
						if config.FIND_CVE {
							method.CveScan(nil)
						}
		
						if config.JSON_OUTPUT {
							if buf, err := json.Marshal(method.Result()); err != nil {
								cmd.ErrorLogger.Printf("error in marshal the result, error = %v\n", err)
							} else {
								fmt.Printf("%s\n", buf)
							}
						} else {
							fmt.Printf("Detected Device = %v | Category = %v | Version = %v\n", method.Result().DeviceName, method.Result().Category, method.Result().Version)
						}
					}
				})
			}
			wg.Wait()
		}
	}
	
	return nil
}

func DetectDeviceBaseURL(content string) (error) {
	var wg sync.WaitGroup
	m := model.GatherModuleSructure{
		Protocol: "http",
		Banner: map[string]any{
			"response": map[string]any{
				"body": content,
			},
		},
	}

	handlers, err := modules.NewModule(m.Protocol)
	if err != nil {
		return err
	} else {
		for method10 := range slices.Chunk(handlers, 10) {
			for _, method := range method10 {				
				wg.Go(func(){
					if res := method.Filters(m.Banner); res {
						method.SetCategory()
						method.SetDeviceName()
						method.DeviceScan(m.Banner)
						if config.FIND_CVE {
							method.CveScan(nil)
						}
		
						if config.JSON_OUTPUT {
							if buf, err := json.Marshal(method.Result()); err != nil {
								cmd.ErrorLogger.Printf("error in marshal the result, error = %v\n", err)
							} else {
								fmt.Printf("%s\n", buf)
							}
						} else {
							fmt.Printf("Detected Device = %v | Category = %v | Version = %v\n", method.Result().DeviceName, method.Result().Category, method.Result().Version)
						}
					}
				})
			}
			wg.Wait()
		}
	}
	
	return nil
}