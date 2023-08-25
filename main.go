package main

import (
	"flag"
	"fmt"
	"github.com/xquare-team/envoy-middleware-test/pkg/auth"
	"os"
	"os/signal"
	"syscall"
)
 
var (
	grpcPort = flag.String("grpc", "9000", "gRPC server port")
)

func main() {
	flag.Parse()
	s := auth.NewExtAuthzServer()

	go s.Run(fmt.Sprintf(":%s", *grpcPort))
	defer s.Stop()

	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
