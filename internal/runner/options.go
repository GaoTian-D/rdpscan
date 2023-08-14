package runner

type Options struct {
	ParallelThreads int
	InputsFilePath  string
	IP              string
	OutputPath      string
	Port            int
	ConnectTimeOut  int
	ReadTimeOut     int
	Version         string
}
