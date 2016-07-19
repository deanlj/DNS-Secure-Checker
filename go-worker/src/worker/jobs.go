package worker
import (
  "Process"
)
func Webwork(domain string,result chan string,end chan bool){
  defer func(){
    result<-"流程结束"
    end<-true
  }()
  Process.WebProcessDNSMain(domain,result)
  // end<-true
  Process.WebProcessDNSSecMain(domain,result)
}
