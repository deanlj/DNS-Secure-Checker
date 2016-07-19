package main

import (
        // "fmt"
        "log"
        "encoding/json"
        "worker"
        "util"
        "github.com/streadway/amqp"
)
func main() {
        conn, err := amqp.Dial("amqp://mike:123456@localhost")
        util.FailOnError(err, "连接Rabbitmq失败", "连接Rabbitmq成功")
        defer conn.Close()
        ch, err := conn.Channel()
        util.FailOnError(err, "打开channel失败", "打开channel成功")
        defer ch.Close()
        q, err := ch.QueueDeclare(
                "dns_queue", // name
                false,       // durable
                false,       // delete when usused
                false,       // exclusive
                false,       // no-wait
                nil,         // arguments
        )
        util.FailOnError(err, "声明队列失败","声明队列成功")
        err = ch.Qos(
                10,     // prefetch count
                0,     // prefetch size
                false, // global
        )
        util.FailOnError(err, "设置QOS失败","设置QOS成功")
        msgs, err := ch.Consume(
                q.Name, // queue
                "",     // consumer
                false,  // auto-ack
                false,  // exclusive
                false,  // no-local
                false,  // no-wait
                nil,    // args
        )
        util.FailOnError(err, "注册consumer失败","注册consumer成功")
        for{
            log.Printf(" [*] 等待rpc请求...")
            for d := range msgs {
                      go func(){
                        result_chan:=make(chan util.ResonseMessage)
                        end_chan:=make(chan bool)
                        message:=util.RequestMessage{}
                        err:=json.Unmarshal(d.Body, &message)
                        util.FailOnError(err, "对象格式转换失败","对象格式转换成功")
                        log.Printf("接收到消息：%+v\n",message)
                        // result_chan<-"服务器已接收到信息，处理查询中"
                        go func(){
                          worker.Webwork(message.Domain,result_chan,end_chan)
                        }()
                        for{
                           select{
                              case response:=<-result_chan:
                                m,err:=json.Marshal(response)
                                err = ch.Publish(
                                        "",        // exchange
                                        d.ReplyTo, // routing key
                                        false,     // mandatory
                                        false,     // immediate
                                        amqp.Publishing{
                                                ContentType:   "text/plain",
                                                CorrelationId: d.CorrelationId,
                                                Body:          []byte(string(m)),
                                        })
                                util.FailOnError(err, "发布消息失败","发布消息成功")
                                case <-end_chan:
                                    log.Printf("[DEBUG]结束channel")
                                    goto NEXT
                              }
                          }
                          NEXT:
                          log.Printf("[DEBUG]关闭channel")
                          close(result_chan)
                          close(end_chan)
                          d.Ack(false)
                          log.Printf("[DEBUG]关闭ack")
                      }()
              }

        }
}
