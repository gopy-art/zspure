package handler

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
)

type RedisQueue struct {
	URL       string          `json:"address" yaml:"address"`
	Password  string          `json:"password" yaml:"password"`
	DB        int             `json:"db" yaml:"db"`
	BatchSize int             `json:"batch_size" yaml:"batch_size"`
	QueueName string          `json:"queue_name" yaml:"queue_name"`
	RQClient  *redis.Client   `json:"-"`
	Ctx       context.Context `json:"-"`
}

func (r *RedisQueue) RedisQueueConnection() error {
	if r.QueueName == "" {
		return fmt.Errorf("queue_name can not be empty")
	}
	r.Ctx = context.Background()
	if r.BatchSize == 0 {
		r.BatchSize = 1
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:     r.URL,
		Password: r.Password,
		DB:       r.DB,
	})
	r.RQClient = rdb
	defer r.RQClient.Conn().Close()
	return nil
}

func (r *RedisQueue) Push(task string) error {
	err := r.RQClient.RPush(r.Ctx, r.QueueName, task).Err()
	if err != nil {
		return err
	}
	return nil
}

func (r *RedisQueue) Pop() ([]string, error) {
	result, err := r.RQClient.BLPop(r.Ctx, 0, r.QueueName).Result()
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (r *RedisQueue) Take(tasks []string) error {
	for i := 0; i < len(tasks); i += r.BatchSize {
		end := i + r.BatchSize
		if end > len(tasks) {
			end = len(tasks)
		}
		chunk := make([]interface{}, end-i)
		for j, v := range tasks[i:end] {
			chunk[j] = v
		}
		err := r.RQClient.RPush(r.Ctx, r.QueueName, chunk...).Err()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *RedisQueue) CleanUp() error {
	err := r.RQClient.FlushDB(r.Ctx).Err()
	if err != nil {
		return err
	}
	return nil
}
