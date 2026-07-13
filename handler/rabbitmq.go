package handler

import (
	"fmt"
	amqp "github.com/rabbitmq/amqp091-go"
)

type RabbitMq struct {
	URL       string        `json:"address" yaml:"address"`
	Username  string        `json:"username" yaml:"username"`
	Password  string        `json:"password" yaml:"password"`
	QueueName string        `json:"queue_name" yaml:"queue_name"`
	Channel   *amqp.Channel `json:"-"`
}

func (r *RabbitMq) RabbitMqConnection() error {
	if r.QueueName == "" {
		return fmt.Errorf("queue_name can not be empty")
	}
	conn, err := amqp.Dial(fmt.Sprintf("amqp://%v:%v@%v/", r.Username, r.Password, r.URL))
	if err != nil {
		return err
	}
	defer conn.Close()
	ch, err := conn.Channel()

	r.Channel = ch
	return nil
}

func (r *RabbitMq) Push(task string) error {
	q, errCh := r.Channel.QueueDeclare(
		r.QueueName,
		true,
		false,
		false,
		false,
		nil,
	)
	if errCh != nil {
		return errCh
	}

	errPub := r.Channel.Publish(
		"",
		q.Name,
		false,
		false,
		amqp.Publishing{
			ContentType:  "application/json",
			DeliveryMode: amqp.Persistent,
			Body:         []byte(task),
		},
	)
	if errPub != nil {
		return errPub
	}
	return nil
}

func (r *RabbitMq) CleanUp() error {
	_, err := r.Channel.QueuePurge(r.QueueName, false)
	if err != nil {
		return err
	}
	return nil
}
