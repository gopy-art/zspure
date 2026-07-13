package handler_test

import (
	"fmt"
	"sync"
	"testing"
	"time"
	"zspure/handler"
)

func TestRedisQueueConnection(t *testing.T) {
	rq := handler.RedisQueue{
		URL:       "localhost:6379",
		DB:        0,
		Password:  "",
		QueueName: "result",
	}
	connErr := rq.RedisQueueConnection()
	if connErr != nil {
		t.Fatal(connErr.Error())
	}
	fmt.Printf("redis queue connection was success")
}

func TestRedisQueuePushAndPop(t *testing.T) {
	rq := handler.RedisQueue{
		URL:       "localhost:6379",
		DB:        0,
		Password:  "",
		QueueName: "result",
	}
	connErr := rq.RedisQueueConnection()
	if connErr != nil {
		t.Fatal(connErr.Error())
	}
	EnqueueErr := rq.Push("test task 1")
	if EnqueueErr != nil {
		t.Fatal(EnqueueErr.Error())
	}
	result, popErr := rq.Pop()
	if popErr != nil {
		t.Fatal(popErr.Error())
	}
	fmt.Printf("DequeueTask:%v\n", result)
}

func TestRedisQueueMultiPushAndPop(t *testing.T) {
	rq := handler.RedisQueue{
		URL:       "localhost:6379",
		DB:        0,
		Password:  "",
		QueueName: "result",
	}
	connErr := rq.RedisQueueConnection()
	if connErr != nil {
		t.Fatal(connErr.Error())
	}
	for i := 0; i < 10; i++ {
		EnqueueErr := rq.Push(fmt.Sprintf("test task %v", i))
		if EnqueueErr != nil {
			t.Fatal(EnqueueErr.Error())
		}
	}
	for i := 0; i < 10; i++ {
		result, popErr := rq.Pop()
		if popErr != nil {
			t.Fatal(popErr.Error())
		}
		fmt.Printf("DequeueTask:%v\n", result)
	}
}

func TestRedisQueueConcurrentPushAndPop(t *testing.T) {
	rq := handler.RedisQueue{
		URL:       "localhost:6379",
		DB:        0,
		Password:  "",
		QueueName: "result",
	}
	connErr := rq.RedisQueueConnection()
	if connErr != nil {
		t.Fatal(connErr.Error())
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		for i := 0; i < 10; i++ {
			EnqueueErr := rq.Push(fmt.Sprintf("test task %v", i))
			if EnqueueErr != nil {
				t.Fatal(EnqueueErr.Error())
			}
			time.Sleep(time.Millisecond * 300)
		}
		wg.Done()
	}()

	go func() {
		for i := 0; i < 10; i++ {
			result, popErr := rq.Pop()
			if popErr != nil {
				t.Fatal(popErr.Error())
			}
			fmt.Printf("DequeueTask:%v\n", result)
			time.Sleep(time.Millisecond * 500)
		}
		wg.Done()
	}()
	wg.Wait()
}

func TestRedisQueueTakeAndPop(t *testing.T) {
	rq := handler.RedisQueue{
		URL:       "localhost:6379",
		DB:        0,
		BatchSize: 3,
		Password:  "",
		QueueName: "result",
	}
	connErr := rq.RedisQueueConnection()
	if connErr != nil {
		t.Fatal(connErr.Error())
	}
	tasks := []string{}
	for i := 0; i < 10; i++ {
		tasks = append(tasks, fmt.Sprintf("test task %v", i))
	}
	TakeErr := rq.Take(tasks)
	if TakeErr != nil {
		t.Fatal(TakeErr.Error())
	}

	for i := 0; i < 10; i++ {
		result, popErr := rq.Pop()
		if popErr != nil {
			t.Fatal(popErr.Error())
		}
		fmt.Printf("DequeueTask:%v\n", result)
		time.Sleep(time.Millisecond * 500)
	}

}

func TestRedisQueueMultiPushAndCleanUp(t *testing.T) {
	rq := handler.RedisQueue{
		URL:       "localhost:6379",
		DB:        0,
		Password:  "",
		QueueName: "result",
	}
	connErr := rq.RedisQueueConnection()
	if connErr != nil {
		t.Fatal(connErr.Error())
	}
	for i := 0; i < 10; i++ {
		EnqueueErr := rq.Push(fmt.Sprintf("test task %v", i))
		if EnqueueErr != nil {
			t.Fatal(EnqueueErr.Error())
		}
	}

	CleanUpErr := rq.CleanUp()
	if CleanUpErr != nil {
		t.Fatal(CleanUpErr.Error())
	}
	fmt.Printf("successfully cleanup the queue")
	result, popErr := rq.Pop()
	if popErr != nil {
		t.Fatal(popErr.Error())
	}
	fmt.Printf("DequeueTask:%v\n", result)
}

func TestRedisQueueCleanUp(t *testing.T) {
	rq := handler.RedisQueue{
		URL:       "localhost:6379",
		DB:        0,
		Password:  "",
		QueueName: "result",
	}
	connErr := rq.RedisQueueConnection()
	if connErr != nil {
		t.Fatal(connErr.Error())
	}

	CleanUpErr := rq.CleanUp()
	if CleanUpErr != nil {
		t.Fatal(CleanUpErr.Error())
	}
	fmt.Printf("successfully cleanup the queue\n")
}
