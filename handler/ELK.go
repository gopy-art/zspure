package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
	conf "zspure/config"
	"zspure/config/cmd"

	"github.com/elastic/go-elasticsearch/v8"
)

type Elastic struct {
	URL      []string              `json:"address"`
	APIKey   string                `json:"apikey"`
	CveIndex string                `json:"-"`
	ES       *elasticsearch.Client `json:"-"`
}

func (e *Elastic) ElasticConnection() error {
	if es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: e.URL,
		APIKey:    e.APIKey,
		Transport: &http.Transport{
			ExpectContinueTimeout: time.Minute * 3,
			TLSHandshakeTimeout:   time.Minute * 3,
			MaxIdleConnsPerHost:   2,
			ResponseHeaderTimeout: time.Minute * 3,
			DialContext:           (&net.Dialer{Timeout: time.Minute * 3}).DialContext,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
			},
		},
	}); err != nil {
		return err
	} else {
		e.ES = es
		return nil
	}
}

// BuildQuery builds a search body based on filters.
// - If filters == nil => match_all
// - If operator == "or" => use bool.should (OR semantics)
// - If operator == "and" => use bool.filter (AND semantics)
// - If a key ends with ".keyword" => use term (exact match)
// - Otherwise => use match (full-text)
func (e *Elastic) BuildQuery(size int, operator string, filters map[string]interface{}) map[string]interface{} {
	q := map[string]interface{}{"size": size}

	if filters == nil {
		q["query"] = map[string]interface{}{"match_all": map[string]interface{}{}}
		return q
	}

	clauses := make([]interface{}, 0, len(filters))
	for field, value := range filters {
		if strings.HasSuffix(field, ".keyword") {
			// exact match on keyword subfield
			clauses = append(clauses, map[string]interface{}{
				"term": map[string]interface{}{field: value},
			})
		} else {
			// full-text match
			clauses = append(clauses, map[string]interface{}{
				"match": map[string]interface{}{
					field: map[string]interface{}{
						"query":    value,
						"operator": operator, // force all terms in value to match
					},
				},
			})
		}
	}

	boolQuery := map[string]interface{}{}

	if strings.ToLower(operator) == "or" {
		boolQuery["should"] = clauses
		boolQuery["minimum_should_match"] = 1
	} else {
		// default AND behavior
		boolQuery["filter"] = clauses
	}

	q["query"] = map[string]interface{}{"bool": boolQuery}
	q["sort"] = []interface{}{
		map[string]interface{}{
			"cve.cisaActionDue": map[string]interface{}{
				"order": "desc",
			},
		},
	}

	return q
}

func (e *Elastic) GatherAllDataInQueue(queue chan map[string]interface{}, index string, config map[string]interface{}) {
	// Build the base query
	query := map[string]interface{}{}

	switch conf.ORDER {
	case "desc":
		query = map[string]interface{}{
			"size": conf.BatchSize,
			"sort": []interface{}{
				map[string]interface{}{
					"timestamp": map[string]interface{}{
						"order": "desc", // newest to oldest
					},
				},
			},
		}
	case "asc":
		query = map[string]interface{}{
			"size": conf.BatchSize,
		}
	default:
		log.Fatal("The order input is invalid")
	}

	// If filters are provided, build a bool.query.filter
    if config != nil {
        boolQuery := map[string]interface{}{}
        filterList := make([]interface{}, 0)
        mustNotList := make([]interface{}, 0)
        shouldList := make([]interface{}, 0)

        // Term filters (e.g., "status": "success")
        if termFilters, ok := config["term"].(map[string]interface{}); ok {
            for field, value := range termFilters {
                filterList = append(filterList, map[string]interface{}{
                    "term": map[string]interface{}{
                        field: value,
                    },
                })
            }
        }

        // must_not exists filters
        if mustNotFields, ok := config["must_not_exists"].([]string); ok {
            for _, field := range mustNotFields {
                mustNotList = append(mustNotList, map[string]interface{}{
                    "exists": map[string]interface{}{
                        "field": field,
                    },
                })
            }
        }

        // Should queries - support different query types
        if shouldQueries, ok := config["should"].([]map[string]interface{}); ok {
            queryType := "match_phrase" // default to phrase matching
            if qt, ok := config["query_type"].(string); ok {
                queryType = qt
            }

            for _, shouldQuery := range shouldQueries {
                for field, value := range shouldQuery {
                    switch queryType {
                    case "term":
                        shouldList = append(shouldList, map[string]interface{}{
                            "term": map[string]interface{}{
                                field + ".keyword": value,
                            },
                        })
                    case "match":
                        shouldList = append(shouldList, map[string]interface{}{
                            "match": map[string]interface{}{
                                field: value,
                            },
                        })
                    case "match_phrase":
                        fallthrough
                    default:
                        shouldList = append(shouldList, map[string]interface{}{
                            "match_phrase": map[string]interface{}{
                                field: value,
                            },
                        })
                    }
                }
            }
        }

        // Build the final bool query
        if len(filterList) > 0 {
            boolQuery["filter"] = filterList
        }
        if len(mustNotList) > 0 {
            boolQuery["must_not"] = mustNotList
        }
        if len(shouldList) > 0 {
            boolQuery["should"] = shouldList
            boolQuery["minimum_should_match"] = 1
        }

        query["query"] = map[string]interface{}{
            "bool": boolQuery,
        }
    } else {
        query["query"] = map[string]interface{}{
            "match_all": map[string]interface{}{},
        }
    }

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		log.Fatalf("Error encoding query: %s", err)
	}

	res, err := e.ES.Search(
		e.ES.Search.WithContext(context.Background()),
		e.ES.Search.WithIndex(index),
		e.ES.Search.WithBody(&buf),
		e.ES.Search.WithScroll(2*time.Minute), // keep the search context open for 2 minutes
	)
	if err != nil {
		log.Fatalf("Error getting response: %s", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Fatalf("Error response: %s", res.String())
	}

	// Parse the initial response
	var r map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		log.Fatalf("Error parsing response: %s", err)
	}

	// Extract scroll_id (safely)
	scrollID := ""
	if sid, ok := r["_scroll_id"]; ok && sid != nil {
		scrollID = fmt.Sprintf("%v", sid)
	}

	// Ensure cleanup of scroll no matter what
	defer func() {
		clr, err := e.ES.ClearScroll(e.ES.ClearScroll.WithScrollID(scrollID))
		if err != nil {
			log.Printf("Failed to clear scroll: %v", err)
		} else {
			_ = clr.Body.Close()
		}
	}()

	totalHits := int(r["hits"].(map[string]interface{})["total"].(map[string]interface{})["value"].(float64))
	cmd.InfoLogger.Printf("Total documents: %d\n", totalHits)

	// First batch of hits
	hits := r["hits"].(map[string]interface{})["hits"].([]interface{})
	for _, hit := range hits {
		hit.(map[string]interface{})["_source"].(map[string]interface{})["_id"] = hit.(map[string]interface{})["_id"].(string)
		hit.(map[string]interface{})["_source"].(map[string]interface{})["_index"] = hit.(map[string]interface{})["_index"].(string)
		queue <- hit.(map[string]interface{})["_source"].(map[string]interface{})
	}

	// Keep scrolling until no more hits
	for {
		scrollRes, err := e.ES.Scroll(
			e.ES.Scroll.WithScrollID(scrollID),
			e.ES.Scroll.WithScroll(2*time.Minute),
		)
		if err != nil {
			log.Fatalf("Error scrolling: %s", err)
		}

		var sr map[string]interface{}
		if err := json.NewDecoder(scrollRes.Body).Decode(&sr); err != nil {
			scrollRes.Body.Close()
			log.Fatalf("Error parsing scroll response: %s", err)
		}
		scrollRes.Body.Close()

		if scrollRes.IsError() {
			break
		}

		hits := sr["hits"].(map[string]interface{})["hits"].([]interface{})
		if len(hits) == 0 {
			break
		}

		for _, hit := range hits {
			hit.(map[string]interface{})["_source"].(map[string]interface{})["_id"] = hit.(map[string]interface{})["_id"].(string)
			hit.(map[string]interface{})["_source"].(map[string]interface{})["_index"] = hit.(map[string]interface{})["_index"].(string)
			queue <- hit.(map[string]interface{})["_source"].(map[string]interface{})
		}

		scrollID = sr["_scroll_id"].(string)
	}
}

func (e *Elastic) GatherAllDataInMap(index, operator string, config map[string]interface{}) []map[string]interface{} {
	const batchSize = 1000
	query := e.BuildQuery(batchSize, operator, config)

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		log.Fatalf("Error encoding query: %s", err)
	}

	res, err := e.ES.Search(
		e.ES.Search.WithContext(context.Background()),
		e.ES.Search.WithIndex(index),
		e.ES.Search.WithBody(&buf),
		e.ES.Search.WithScroll(2*time.Minute), // keep the search context open for 2 minutes
	)
	if err != nil {
		log.Fatalf("Error getting response: %s", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		log.Fatalf("Error response: %s", res.String())
	}

	// Parse the initial response
	var r map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		log.Fatalf("Error parsing response: %s", err)
	}

	scrollID := r["_scroll_id"].(string)
	allData := make([]map[string]interface{}, 0)

	// First batch of hits
	hits := r["hits"].(map[string]interface{})["hits"].([]interface{})
	for _, hit := range hits {
		allData = append(allData, hit.(map[string]interface{})["_source"].(map[string]interface{}))
	}

	// Keep scrolling until no more hits
	for {
		scrollRes, err := e.ES.Scroll(
			e.ES.Scroll.WithScrollID(scrollID),
			e.ES.Scroll.WithScroll(2*time.Minute),
		)
		if err != nil {
			log.Fatalf("Error scrolling: %s", err)
		}
		defer scrollRes.Body.Close()

		if scrollRes.IsError() {
			break
		}

		var sr map[string]interface{}
		if err := json.NewDecoder(scrollRes.Body).Decode(&sr); err != nil {
			log.Fatalf("Error parsing scroll response: %s", err)
		}

		hits := sr["hits"].(map[string]interface{})["hits"].([]interface{})
		if len(hits) == 0 {
			break
		}

		for _, hit := range hits {
			allData = append(allData, hit.(map[string]interface{})["_source"].(map[string]interface{}))
		}

		scrollID = sr["_scroll_id"].(string)
	}

	return allData
}

func (e *Elastic) UpdateSingleData(index, id string, buf bytes.Buffer) error {
	// Send the update request
	res, err := e.ES.Update(
		index, // Index name
		id,    // Document ID
		&buf,  // JSON body
		e.ES.Update.WithContext(context.Background()),
	)
	if err != nil {
		return fmt.Errorf("error updating document: %s", err)
	}
	defer res.Body.Close()

	// Check response
	if res.IsError() {
		return fmt.Errorf("error response from Elasticsearch: %s", res.String())
	} else {
		return nil
	}
}

// deleteFields removes specific fields from a document in Elasticsearch
func (e *Elastic) DeleteFields(indexName, docID string, fields []string) error {
	// Build Painless script that removes each field
	scriptLines := make([]string, len(fields))
	for i, field := range fields {
		scriptLines[i] = fmt.Sprintf("ctx._source.remove('%s');", field)
	}
	script := strings.Join(scriptLines, " ")

	// Prepare update request body
	body := map[string]interface{}{
		"script": map[string]string{
			"source": script,
		},
	}
	data, _ := json.Marshal(body)

	// Execute update
	res, err := e.ES.Update(
		indexName,
		docID,
		bytes.NewReader(data),
		e.ES.Update.WithContext(context.Background()),
	)
	if err != nil {
		return fmt.Errorf("error updating document: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("update failed: %s", res.String())
	}

	cmd.SuccessLogger.Printf("Successfully deleted fields %v from document %s\n", fields, docID)
	return nil
}