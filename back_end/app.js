var express = require('express');
var app = express();
var uuid = require('uuid');
var http = require('http').Server(app);
var bodyParser = require('body-parser');
var io = require("socket.io")(http)
var formatMessage=function(message,type,err){
  return {"Message":message,"Type":type,"Error":err||""};
}





// amqp code start point

var amqp = require('amqplib/callback_api');
var amqpConn= null;
var pubChannel = null;

function startConnRabbitMQ(){
  amqp.connect("amqp://mike:123456@localhost", function(err, conn) {
    if(err){
      console.log("[x]Error:"+err);
      return
    }
    conn.on("error",function(err){
      if(err.message!=="Connection closing"){
        console.log("[x]Error:"+err);
        return
      }
    });
    conn.on("close",function(){
      console.log("[x]Rabbitmq is closed ,trying restart connect after 1s...")
      return setTimeout(startConnRabbitMQ,1000);
    });
    amqpConn=conn;

    console.log("[*]Rabbitmq connect is ready now!");
    startChannel();
  });
}

function startChannel(){
  amqpConn.createConfirmChannel(function(err,ch){
    if(err){
      console.log("[x]Error:"+err);
      return
    }
    ch.on("error",function(err){
        console.log("[x]Error:"+err);
        return
    });
    ch.on("close",function(){
      console.log("[*]Rabbitmq channel is closed")
      return
    });
    ch.assertQueue("dns_queue", {durable: false});
    pubChannel=ch;

    console.log("[*]Rabbitmq channel is ready now!")
  })
}
startConnRabbitMQ();
// io操作代码

io.on("connection",function(socket){
  console.log('A user connected');
  socket.emit('welcome',formatMessage("欢迎使用dns查询系统"))
  // 断开时候的提示
  socket.on('disconnect', function(){
   console.log('user disconnected');
  });
  socket.on('domain',function(data){
    console.log('Data:'+data)
    //  传递给后端的rabbitmq服务器
    var queue_data={domain:data,id:uuid.v1()}
    try {
      pubChannel.assertQueue('', {exclusive: true}, function(err, q) {
            var corr = uuid.v1();
            console.log(' [x] Requesting dns for (%s)', queue_data.domain);
            pubChannel.consume(q.queue, function(msg) {
              if (msg.properties.correlationId == corr) {
                var response_data=msg.content.toString();
                console.log(' [.] 获得worker反馈 %s',response_data);
                socket.emit('message',formatMessage(response_data))
              }
            }, {noAck: true});
            pubChannel.sendToQueue('dns_queue',
            new Buffer(JSON.stringify(queue_data)),
            { correlationId: corr, replyTo: q.queue });
          });
    } catch (e) {
        console.log(e)
    }

  });
});


// io操作代码结束
// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));
// parse application/json
app.use(bodyParser.json());

app.get('/', function (req, res) {
  res.sendFile(__dirname + '/index.html');
});

app.get("/dns",function(req,res){
  console.log("Get request for dns");
});

app.post("/dns",function(req,res){
  //  res.json(req.body.domain);
   if(typeof req.body.domain==='undefined'){
     res.status(400).json({"Error":"No domain data was posted!"});
     return
   }
  //  传递给后端的rabbitmq服务器
  try {
    pubChannel.publish("dns","",new Buffer(JSON.stringify(req.body)),{persistent:true},function(err,ok){
      if (err){
        console.log(err)
        res.status(500).json({"Error":err});
        return
      }else{
        res.status(200).json({"Message":"Success post request to backend rabbitmq"})
        return
      }
    })
  } catch (e) {
      console.log(e)
      res.status(500).json({"Error":e})
      return
  }
});


http.listen(5000,function(){
  var host = http.address().address;
  var port = http.address().port;
  console.log('DNS App is listening at http://%s:%s', host, port);
});
