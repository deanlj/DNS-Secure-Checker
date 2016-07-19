package worker
import (
  "Process"
  "util"
  "sync"
)
func Webwork(domain string,result chan util.ResonseMessage,end chan bool){
  defer func(){
    Process.SendToChannel("查询流程结束","","end",result)
    end<-true
  }()
  var wg sync.WaitGroup
  wg.Add(2)
  go func(){
    defer  wg.Done()
    Process.WebProcessDNSMain(domain,result)
  }()
  go func(){
    defer wg.Done()
    Process.WebProcessDNSSecMain(domain,result)
  }()
  wg.Wait()
}
