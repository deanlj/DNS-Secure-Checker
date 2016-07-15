package main

import (
        "fmt"
        "log"
        "strconv"
        "encoding/json"
        "github.com/streadway/amqp"
)

type Message struct{
  Domain string `json:"domain"`
  ID  string `json:"id"`
}

func failOnError(err error,error_message string,success string) {
        if err != nil {
                log.Fatalf("%s: %s", error_message, err)
                panic(fmt.Sprintf("%s: %s", error_message, err))
        }else{
                log.Println(success)
        }
}
func main() {
        conn, err := amqp.Dial("amqp://mike:123456@localhost")
        failOnError(err, "连接Rabbitmq失败", "连接Rabbitmq成功")
        defer conn.Close()

        ch, err := conn.Channel()
        failOnError(err, "打开channel失败", "打开channel成功")
        defer ch.Close()

        q, err := ch.QueueDeclare(
                "dns_queue", // name
                false,       // durable
                false,       // delete when usused
                false,       // exclusive
                false,       // no-wait
                nil,         // arguments
        )
        failOnError(err, "声明队列失败","声明队列成功")

        err = ch.Qos(
                10,     // prefetch count
                0,     // prefetch size
                false, // global
        )
        failOnError(err, "设置QOS失败","设置QOS成功")

        msgs, err := ch.Consume(
                q.Name, // queue
                "",     // consumer
                false,  // auto-ack
                false,  // exclusive
                false,  // no-local
                false,  // no-wait
                nil,    // args
        )
        failOnError(err, "注册consumer失败","注册consumer成功")

        forever := make(chan bool)

        go func() {
                for d := range msgs {
                        message:=Message{}
                        err:=json.Unmarshal(d.Body, &message)
                        failOnError(err, "对象格式转换失败","对象格式转换成功")

                        // log.Printf(" [.] fib(%d)", n)
                        response := 42
                        fmt.Printf("接收到消息：%v",message)
                        err = ch.Publish(
                                "",        // exchange
                                d.ReplyTo, // routing key
                                false,     // mandatory
                                false,     // immediate
                                amqp.Publishing{
                                        ContentType:   "text/plain",
                                        CorrelationId: d.CorrelationId,
                                        Body:          []byte(strconv.Itoa(response)),
                                })
                        failOnError(err, "发布消息失败","发布消息成功")
                        d.Ack(false)
                }
        }()

        log.Printf(" [*] 等待rpc请求...")
        <-forever
}
