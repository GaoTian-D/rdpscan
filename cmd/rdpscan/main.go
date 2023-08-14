package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"rdpscan/internal/runner"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

var (
	options = &runner.Options{} // 命令行启动参数
	COUNT   = 0
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	if err := readFlags(); err != nil {
		gologger.Fatal().Msgf("参数解析失败: %s\n", err)
	}
	if options.InputsFilePath == "" && options.IP == "" {
		gologger.Fatal().Msg("必须使用 -f 或 -i 指定作为输入\n")
	}
	if options.Port > 65535 || options.Port < 0 {
		gologger.Fatal().Msg("端口号 -p 有误\n")
	}
	var inputQueue = make(chan string, 512)
	var outputQueue = make(chan string, 64)

	// 输入扫描源
	go func() {
		linebyLineScan(inputQueue) // 后台 routine 读取
	}()

	if options.OutputPath != "" {
		f, err := newFileOutput(options.OutputPath)
		if err != nil {
			gologger.Fatal().Msgf("无法创建文件输出!\n")
		}
		go func() {
			for {
				banner := <-outputQueue
				_, err := f.WriteString(banner + "\n")
				if err != nil {
					gologger.Error().Msgf("写文件错误: %s!\n", banner)
				}
			}
		}()
	} else {
		go func() {
			for {
				banner := <-outputQueue
				gologger.Print().Msgf("[+] %s\n", banner)
			}
		}()
	}
	rdpRunner, err := runner.New(inputQueue, options.ParallelThreads, options.ConnectTimeOut, options.ReadTimeOut, outputQueue)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	rdpRunner.Start()
	gologger.Print().Msgf("[+] 读取待扫描源完成, 总 IP 数 %d\n", COUNT)
}

func readFlags() error {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`rdpscan 用于扫描 Windows 远程桌面服务`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&options.InputsFilePath, "file", "f", "", "指定目标文件(行示例 ip:port, 不带端口则默认 3389)"),
		flagSet.StringVarP(&options.IP, "ip", "i", "", "指定单独扫描的 IP"),
		flagSet.IntVarP(&options.Port, "port", "p", 3389, "指定单独扫描的端口"),
		flagSet.IntVarP(&options.ConnectTimeOut, "connect-timeout", "ct", 4, "默认 rdp 连接超时"),
		flagSet.IntVarP(&options.ReadTimeOut, "read-timeout", "rt", 4, "默认 rdp 读取超时"),
		flagSet.StringVarP(&options.OutputPath, "output", "o", "", "结果输出文件"),
	)

	flagSet.CreateGroup("ratelimit", "Rate-Limit",
		flagSet.IntVarP(&options.ParallelThreads, "concurrency", "c", 12, "并发扫描数"),
	)
	if err := flagSet.Parse(); err != nil {
		return errors.Wrap(err, "could not parse flags")
	}
	return nil
}

func newFileOutput(file string) (*os.File, error) {
	f, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// 逐行读取文件，传入 queue 队列（生产者）
func linebyLineScan(queue chan string) {
	if options.IP != "" {
		COUNT++
		if strings.Contains(options.IP, ":") {
			queue <- options.IP
		} else {
			queue <- fmt.Sprintf("%s:%d", options.IP, options.Port)
		}
	}
	if options.InputsFilePath == "" {
		// 如果未指定文件直接 return
		return
	}
	file, err := os.Open(options.InputsFilePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	buf := []byte{}
	scanner := bufio.NewScanner(file)
	// 增加缓冲区到 1kb
	scanner.Buffer(buf, 1*1024)
	for scanner.Scan() {
		COUNT++
		s := strings.TrimSpace(scanner.Text())
		if len(s) > 21 || len(s) < 7 {
			// IP:Port 长度异常
			continue
		}
		if strings.Index(s, ":") == -1 {
			queue <- fmt.Sprintf("%s:3389", options.IP)
		} else {
			queue <- s // 不断写入
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
