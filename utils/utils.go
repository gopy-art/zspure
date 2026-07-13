package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"zspure/config"
	"zspure/config/cmd"
	"zspure/handler"
	"zspure/modules/model"

	"gopkg.in/yaml.v3"
)

type OutputConfigs struct {
	Type     string
	RabbitMQ handler.RabbitMq
	Redis    handler.RedisQueue
}

func RemoveDuplicates(input []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, val := range input {
		if !seen[val] {
			seen[val] = true
			result = append(result, val)
		}
	}

	return result
}

func RemoveDuplicatesFromMap(slice []map[string]interface{}) []map[string]interface{} {
	seen := make(map[string]bool)
	result := make([]map[string]interface{}, 0)

	for _, m := range slice {
		b, err := json.Marshal(m)
		if err != nil {
			continue
		}

		key := string(b)
		if !seen[key] {
			seen[key] = true
			result = append(result, m)
		}
	}

	return result
}

func ValidateFlags() error {
	switch config.LOGIC {
	case "execute":
		if config.CONFIG_PATH == "" {
			return fmt.Errorf("in 'execute' mode, config file path should not be empty")
		}
	case "banner":
		if config.TARGETS == "" {
			return fmt.Errorf("--target is undefined")
		}
		if config.PORT == 0 {
			return fmt.Errorf("--port is undefined")
		}
		if ip, err := ValidateIP(config.TARGETS); err != nil {
			return fmt.Errorf("faild to parse targets, error = %v", err)
		} else {
			config.TARGETS = ip
		}
		if err := ValidatePort(config.PORT); err != nil {
			return fmt.Errorf("faild to parse port, error = %v", err)
		}
	case "print":
		break
	case "file":
		if config.STDIN_INPUT {
			if !CheckStdinExist() {
				return fmt.Errorf("in 'file' mode, 'stdin' should not be empty")
			}
		} else {
			if config.INPUTFILE == "" {
				return fmt.Errorf("in 'file' mode, 'input file' should not be empty")
			} else if filepath.Ext(config.INPUTFILE) != ".json" && filepath.Ext(config.INPUTFILE) != ".html" {
				return fmt.Errorf("in 'file' mode, input file should be .html/.json")
			}
		}
		if strings.TrimSpace(config.OUTPUT_STORAGE) != "" {
			if config.OUTPUT_STORAGE != "rabbit" && config.OUTPUT_STORAGE != "redis" {
				return fmt.Errorf("unsupported --output-storage value (rabbit, redis)")
			}
		}
	case "url":
		if config.URL == "" {
			return fmt.Errorf("in 'url' mode, --url flag should not be empty or ignore")
		}
		if strings.TrimSpace(config.OUTPUT_STORAGE) != "" {
			if config.OUTPUT_STORAGE != "rabbit" && config.OUTPUT_STORAGE != "redis" {
				return fmt.Errorf("unsupported --output-storage value (rabbit, redis)")
			}
		}
	default:
		return fmt.Errorf("logic value is invalid")
	}

	return nil
}

func ReadFile(path string) (string, []byte, error) {
	content, err := os.ReadFile(path)
	return string(content), content, err
}

func ReadStdin() (string, []byte, error) {
	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", nil, err
	} else {
		if config.ZGRAB_INPUT {
			data := string(content)

			start := strings.Index(data, "{")
			end := strings.LastIndex(data, "}")

			if start == -1 || end == -1 || end <= start {
				return "", nil, fmt.Errorf("no JSON found in input")
			}

			jsonStr := data[start : end+1]

			return jsonStr, []byte(jsonStr), nil
		}
		return string(content), content, nil
	}
}

func CheckStdinExist() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	/*
		  		On Unix: stdin is a pipe if (info.Mode() & os.ModeCharDevice) == 0
				On Windows: more complex, but often works for detecting redirection
	*/
	if (info.Mode() & os.ModeCharDevice) == 0 {
		return true
	} else {
		return false
	}
}

func GatherCVEOnline(url string) ([]model.CVEStructure, error) {
	var data []model.CVEStructure
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error in fetch the url, error = %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error in read the body of response, error = %v", err)
	}

	var result map[string]interface{}
	if err = json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("error in unmarshal the response, error = %v", err)
	}

	vulnerabilities, ok := result["vulnerabilities"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("error in response format is invalid")
	}

	var cves []map[string]interface{}
	for _, v := range vulnerabilities {
		if cve, ok := v.(map[string]interface{}); ok {
			cves = append(cves, cve)
		}
	}

	prepared := RemoveDuplicatesFromMap(cves)
	if len(result) == 0 {
		return nil, fmt.Errorf("error in utilize the response")
	}
	for _, c := range prepared {
		if len(data) == 10 {
			break
		}
		cveMod := model.NewCVEStructure(c)
		data = append(data, cveMod)
	}

	return data, nil
}

func ValidateIP(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("IP/CIDR cannot be empty")
	}

	if strings.Contains(input, "/") {
		_, _, err := net.ParseCIDR(input)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR format: %s", input)
		}
		return input, nil
	}

	ip := net.ParseIP(input)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", input)
	}
	input += "/32"
	return input, nil
}

func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535 (got %d)", port)
	}
	return nil
}

func ParseOutputConfig(filepath, storage string) (*OutputConfigs, error) {
	if filepath == "" {
		return nil, fmt.Errorf("file config path should not be empty")
	}
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("error in read the config file, error = %v", err)
	}
	var config *OutputConfigs = new(OutputConfigs)
	switch storage {
	case "rabbit":
		if err := yaml.Unmarshal(data, &config.RabbitMQ); err != nil {
			return nil, err
		}
		if config.RabbitMQ.Password == "" {
			return nil, fmt.Errorf("password should not be empty in rabbit config file")
		}
		if config.RabbitMQ.QueueName == "" {
			return nil, fmt.Errorf("queue name should not be empty in rabbit config file")
		}
		if config.RabbitMQ.URL == "" {
			return nil, fmt.Errorf("address should not be empty in rabbit config file")
		}
		if config.RabbitMQ.Username == "" {
			return nil, fmt.Errorf("username should not be empty in rabbit config file")
		}
		config.Type = storage
		return config, nil
	case "redis":
		if err := yaml.Unmarshal(data, &config.Redis); err != nil {
			return nil, err
		}
		if config.Redis.URL == "" {
			return nil, fmt.Errorf("address should not be empty in redis config file")
		}
		if config.Redis.Password == "" {
			return nil, fmt.Errorf("password should not be empty in redis config file")
		}
		if config.Redis.QueueName == "" {
			return nil, fmt.Errorf("queue name should not be empty in redis config file")
		}
		config.Type = storage
		return config, nil
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", storage)
	}
}

func NormalizeOutput(result model.ModuleStructure) {
	switch config.LOGIC {
	case "file", "url":
		if config.OUTPUT_STORAGE == "" {
			if config.JSON_OUTPUT {
				if buf, err := json.Marshal(result); err != nil {
					cmd.ErrorLogger.Printf("error in marshal the result, error = %v\n", err)
				} else {
					fmt.Printf("%s\n", buf)
				}
			} else {
				fmt.Printf("Detected Device = %v | Category = %v | Version = %v\n", result.DeviceName, result.Category, result.Version)
			}
		} else {
			buf, err := json.Marshal(result)
			if err != nil {
				cmd.ErrorLogger.Fatalf("error in marshal the result, error = %v\n", err)
			}
			switch config.OUTPUT_STORAGE {
			case "rabbit":
				conf, err := ParseOutputConfig(config.CONFIG_PATH, "rabbit")
				if err != nil {
					cmd.ErrorLogger.Fatalf("error in parse the config file, error = %v", err)
				}
				if err := conf.RabbitMQ.RabbitMqConnection(); err != nil {
					cmd.ErrorLogger.Fatalf("error in make connection in rabbit, error = %v", err)
				}
				if err := conf.RabbitMQ.Push(string(buf)); err != nil {
					cmd.ErrorLogger.Fatalf("error in push result in rabbit, error = %v", err)
				}
				cmd.SuccessLogger.Println("Result successfully pushed in rabbit queue.")
				break
			case "redis":
				conf, err := ParseOutputConfig(config.CONFIG_PATH, "redis")
				if err != nil {
					cmd.ErrorLogger.Fatalf("error in parse the config file, error = %v", err)
				}
				if err := conf.Redis.RedisQueueConnection(); err != nil {
					cmd.ErrorLogger.Fatalf("error in make connection in redis, error = %v", err)
				}
				if err := conf.Redis.Push(string(buf)); err != nil {
					cmd.ErrorLogger.Fatalf("error in push result in redis, error = %v", err)
				}
				cmd.SuccessLogger.Println("Result successfully pushed in redis queue.")
				break
			}
		}
	}
}
