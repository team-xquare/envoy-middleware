package auth

import (
	authv2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"log"
	"net"
	"sync"
)

const (
	resultAllowed = "allowed"
	resultDenied  = "denied"
)

type (
	extAuthzServerV2 struct {
		checkService CheckService
	}
	extAuthzServerV3 struct {
		checkService CheckService
	}
)

// ExtAuthzServer implements the ext_authz v2/v3 gRPC and HTTP check request API.
type ExtAuthzServer struct {
	grpcServer *grpc.Server
	grpcV2     *extAuthzServerV2
	grpcV3     *extAuthzServerV3
	// For test only
	grpcPort chan int
}

func (s *extAuthzServerV2) logRequest(allow string, request *authv2.CheckRequest) {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	log.Printf("[gRPCv2][%s]: %s%s, attributes: %v\n", allow, httpAttrs.GetHost(),
		httpAttrs.GetPath(),
		request.GetAttributes())
}

// Check implements gRPC v2 check request.
func (s *extAuthzServerV2) Check(ctx context.Context, checkRequest *authv2.CheckRequest) (*authv2.CheckResponse, error) {

	s.logRequest("", checkRequest)

	request := Request{}
	request.FromV2(checkRequest)

	response, err := s.checkService.Check(ctx, &request)
	if err != nil {
		return nil, err
	}
	return response.AsV2(), nil
}

func (s *extAuthzServerV3) logRequest(allow string, request *authv3.CheckRequest) {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	log.Printf("[gRPCv3][%s]: %s%s, attributes: %v\n", allow, httpAttrs.GetHost(),
		httpAttrs.GetPath(),
		request.GetAttributes())
}

// Check implements gRPC v3 check request.
func (s *extAuthzServerV3) Check(ctx context.Context, checkRequest *authv3.CheckRequest) (*authv3.CheckResponse, error) {

	s.logRequest("", checkRequest)

	request := Request{}
	request.FromV3(checkRequest)

	response, err := s.checkService.Check(ctx, &request)
	if err != nil {
		return nil, err
	}

	return response.AsV3(), nil
}

func (s *ExtAuthzServer) startGRPC(address string, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
		log.Printf("Stopped gRPC server")
	}()

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to start gRPC server: %v", err)
		return
	}
	// Store the port for test only.
	s.grpcPort <- listener.Addr().(*net.TCPAddr).Port

	s.grpcServer = grpc.NewServer()
	reflection.Register(s.grpcServer)
	authv2.RegisterAuthorizationServer(s.grpcServer, s.grpcV2)
	authv3.RegisterAuthorizationServer(s.grpcServer, s.grpcV3)

	log.Printf("Starting gRPC server at %s", listener.Addr())
	if err := s.grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve gRPC server: %v", err)
		return
	}
}

func (s *ExtAuthzServer) Run(grpcAddr string) {
	var wg sync.WaitGroup
	wg.Add(2)
	go s.startGRPC(grpcAddr, &wg)
	wg.Wait()
}

func (s *ExtAuthzServer) Stop() {
	s.grpcServer.Stop()
	log.Printf("GRPC server stopped")
}

func getCheckService() CheckService {
	l := logrus.New()
	check := NewCheckService(l)
	return check
}

func NewExtAuthzServer() *ExtAuthzServer {
	return &ExtAuthzServer{
		grpcV2:   &extAuthzServerV2{checkService: getCheckService()},
		grpcV3:   &extAuthzServerV3{checkService: getCheckService()},
		grpcPort: make(chan int, 1),
	}
}
