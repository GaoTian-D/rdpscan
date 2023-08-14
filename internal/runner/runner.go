package runner

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

type Runner struct {
	parallelThreads int
	input           chan string
	connectTimeout  int
	readTimeout     int
	output          chan string
}

func New(input chan string, threads int, ct int, rt int, output chan string) (*Runner, error) {
	runner := &Runner{
		input:           input,
		parallelThreads: threads,
		connectTimeout:  ct,
		readTimeout:     rt,
		output:          output,
	}
	return runner, nil
}

func (r *Runner) Start() {
	defer func() {
		if err := recover(); err != nil {
			customErr := errors.New(fmt.Sprintf("发生未预期的报错(请提交项目 issue): %s", err))
			gologger.Warning().Msgf("%+v", customErr)
		}
	}()
	var sem = make(chan int, r.parallelThreads) // 并发处理和上传限制
	for {
		sem <- 1 // 占用一个并发名额
		select {
		case line := <-r.input:
			host, portStr, err := net.SplitHostPort(line)
			if err != nil {
				continue
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return
			}
			go func(host string, port int) {
				if r.CheckIfRDP(host, port) {
					osinfo, err := DetectOSInfo(host, port)
					if err == nil {
						var line strings.Builder
						line.WriteString(fmt.Sprintf("%s:%d\n", host, port))

						if osinfo.TargetName != "" {
							line.WriteString(fmt.Sprintf("TargetName: %s\n", osinfo.TargetName))
						}
						if osinfo.Product_Version != "" {
							line.WriteString(fmt.Sprintf("Product_Version: %s\n", osinfo.Product_Version))
						}
						if osinfo.OS != "" {
							line.WriteString(fmt.Sprintf("OS: %s\n", osinfo.OS))
						}
						if osinfo.NetBIOS_Domain_Name != "" {
							line.WriteString(fmt.Sprintf("NetBIOS_Domain_Name: %s\n", osinfo.NetBIOS_Domain_Name))
						}
						if osinfo.NetBIOS_Computer_Name != "" {
							line.WriteString(fmt.Sprintf("NetBIOS_Computer_Name: %s\n", osinfo.NetBIOS_Computer_Name))
						}
						if osinfo.DNS_Computer_Name != "" {
							line.WriteString(fmt.Sprintf("DNS_Computer_Name: %s\n", osinfo.DNS_Computer_Name))
						}
						if osinfo.DNS_Domain_Name != "" {
							line.WriteString(fmt.Sprintf("DNS_Domain_Name: %s\n", osinfo.DNS_Domain_Name))
						}
						if osinfo.DNS_Tree_Name != "" {
							line.WriteString(fmt.Sprintf("DNS_Tree_Name: %s\n", osinfo.DNS_Tree_Name))
						}
						if osinfo.System_Time != "" {
							line.WriteString(fmt.Sprintf("System_Time: %s\n", osinfo.System_Time))
						}
						r.output <- line.String()
					} else {
						line := fmt.Sprintf("%s:%d\n", host, port)
						r.output <- line
						// gologger.Warning().Msgf("%s:%d %s\n", host, port, err.Error())
					}
				}
				<-sem // 释放一个
			}(host, port)
		case <-time.After(12 * time.Second):
			// 读取输入完毕
			return
		}
	}
}

var TPKT_Header = []byte{0x03, 0x00, 0x00}

func (r *Runner) CheckIfRDP(host string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), time.Duration(r.connectTimeout)*time.Second)
	if err != nil {
		fmt.Printf("建立 socket 连接 %s 失败: %s\n", host, err.Error())
		return false
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(r.readTimeout) * time.Second))
	if err != nil {
		fmt.Printf("设置 socket 读取超时 %s 失败: %s\n", host, err.Error())
		return false
	}
	defer conn.Close()

	_, err = conn.Write(GenerateRequestPDU("msts")) //append(agent.IV, encryptedBytes...)
	if err != nil {
		fmt.Printf("发送 socket 数据失败: %s\n", err.Error())
		return false
	}
	buf := make([]byte, 1024)

	rlen, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("读取 socket 数据失败: %s\n", err.Error())
		return false
	}
	if rlen > 0 {
		_, err := ParseConnectionConfirm(buf[:rlen])
		if err == nil {
			return true
		}
	}
	return false
}
