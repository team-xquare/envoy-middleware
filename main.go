package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/getsentry/sentry-go"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/xquare-team/envoy-middleware-test/pkg/errors"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

type ValidationError = jwt.ValidationError

type JWTClaims struct {
	Role        string   `json:"role"`
	Authorities []string `json:"authorities"`
	jwt.StandardClaims
}

func (c *JWTClaims) ToJWTToken() string {
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	token, _ := at.SignedString([]byte(jwtSecret))

	return token
}

func ParseJWTToken(jwtToken string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(jwtToken, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	return token.Claims.(*JWTClaims), nil
}

type InvalidHeaderError struct {
	NotAvailableHeaders []string
}

func NewInvalidHeaderError(headers []string) InvalidHeaderError {
	return InvalidHeaderError{headers}
}

func (e InvalidHeaderError) Error() string {
	message := strings.Join(e.NotAvailableHeaders, ", ")
	return "Not available header name: " + message
}

type CheckRequestV2 = envoy_service_auth_v2.CheckRequest   //nolint(golint)
type CheckResponseV2 = envoy_service_auth_v2.CheckResponse //nolint(golint)
type CheckRequestV3 = envoy_service_auth_v3.CheckRequest   //nolint(golint)
type CheckResponseV3 = envoy_service_auth_v3.CheckResponse //nolint(golint)

type Request struct {
	Context map[string]string
	Request http.Request
	ID      string
}

func (r *Request) FromV2(c *CheckRequestV2) *Request {
	r.Request = http.Request{
		URL: &url.URL{
			Scheme:   c.GetAttributes().GetRequest().GetHttp().GetScheme(),
			Host:     c.GetAttributes().GetRequest().GetHttp().GetHost(),
			Path:     c.GetAttributes().GetRequest().GetHttp().GetPath(),
			RawQuery: c.GetAttributes().GetRequest().GetHttp().GetQuery(),
			Fragment: c.GetAttributes().GetRequest().GetHttp().GetFragment(),
		},
		Header: http.Header{},
		Method: c.GetAttributes().GetRequest().GetHttp().GetMethod(),
		Proto:  c.GetAttributes().GetRequest().GetHttp().GetProtocol(),
	}

	for k, v := range c.GetAttributes().GetRequest().GetHttp().GetHeaders() {
		r.Request.Header.Add(k, v)
	}

	r.ID = c.GetAttributes().GetRequest().GetHttp().GetId()
	r.Context = c.GetAttributes().GetContextExtensions()

	return r
}

func (r *Request) FromV3(c *CheckRequestV3) *Request {
	r.Request = http.Request{
		URL: &url.URL{
			Scheme:   c.GetAttributes().GetRequest().GetHttp().GetScheme(),
			Host:     c.GetAttributes().GetRequest().GetHttp().GetHost(),
			Path:     c.GetAttributes().GetRequest().GetHttp().GetPath(),
			RawQuery: c.GetAttributes().GetRequest().GetHttp().GetQuery(),
			Fragment: c.GetAttributes().GetRequest().GetHttp().GetFragment(),
		},
		Header: http.Header{},
		Method: c.GetAttributes().GetRequest().GetHttp().GetMethod(),
		Proto:  c.GetAttributes().GetRequest().GetHttp().GetProtocol(),
	}

	for k, v := range c.GetAttributes().GetRequest().GetHttp().GetHeaders() {
		r.Request.Header.Add(k, v)
	}

	r.ID = c.GetAttributes().GetRequest().GetHttp().GetId()
	r.Context = c.GetAttributes().GetContextExtensions()

	return r
}

type Response struct {
	Allow    bool
	Response http.Response
}

func (r *Response) AsV2() *CheckResponseV2 {
	convertHeaders := func(h http.Header) []*envoy_api_v2_core.HeaderValueOption {
		var headers []*envoy_api_v2_core.HeaderValueOption

		for k, v := range h {
			headers = append(headers,
				&envoy_api_v2_core.HeaderValueOption{
					Header: &envoy_api_v2_core.HeaderValue{Key: k, Value: v[0]},
				},
			)
		}

		return headers
	}

	if r.Allow {
		return &CheckResponseV2{
			Status: &status.Status{Code: int32(codes.OK)},
			HttpResponse: &envoy_service_auth_v2.CheckResponse_OkResponse{
				OkResponse: &envoy_service_auth_v2.OkHttpResponse{
					Headers: convertHeaders(r.Response.Header),
				},
			},
		}
	}

	return &CheckResponseV2{
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &envoy_service_auth_v2.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_service_auth_v2.DeniedHttpResponse{
				Headers: convertHeaders(r.Response.Header),
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode(r.Response.StatusCode),
				},
			},
		},
	}
}

func (r *Response) AsV3() *CheckResponseV3 {
	convertHeaders := func(h http.Header) []*envoy_config_core_v3.HeaderValueOption {
		var headers []*envoy_config_core_v3.HeaderValueOption

		for k, v := range h {
			headers = append(headers,
				&envoy_config_core_v3.HeaderValueOption{
					Header: &envoy_config_core_v3.HeaderValue{Key: k, Value: v[0]},
				},
			)
		}

		return headers
	}

	if r.Allow {
		return &CheckResponseV3{
			Status: &status.Status{Code: int32(codes.OK)},
			HttpResponse: &envoy_service_auth_v3.CheckResponse_OkResponse{
				OkResponse: &envoy_service_auth_v3.OkHttpResponse{
					Headers: convertHeaders(r.Response.Header),
				},
			},
		}
	}

	return &CheckResponseV3{
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &envoy_service_auth_v3.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{
				Headers: convertHeaders(r.Response.Header),
				Status: &envoy_type_v3.HttpStatus{
					Code: envoy_type_v3.StatusCode(r.Response.StatusCode),
				},
			},
		},
	}
}

type CheckService interface {
	Check(context.Context, *Request) (*Response, error)
}

type checkService struct {
	log *logrus.Logger
}

func NewCheckService(l *logrus.Logger) CheckService {
	return &checkService{
		log: l,
	}
}

func (c *checkService) Check(ctx context.Context, request *Request) (*Response, error) {
	c.log.Infof("checking request host: %s, path:%s, id: %s",
		request.Request.URL.Host,
		request.Request.URL.Path,
		request.ID,
	)

	var tokenString string
	var tokenType string

	if c.isAvailableCookie(request) {
		tokenString = c.getAccessTokenFromCookie(request)
	} else {
		availableHeaders := c.findNotAvailableHeader(request)
		if len(availableHeaders) != 0 {
			err := errors.NewInvalidHeaderError(availableHeaders)
			return c.responseUnauthorizedError(err), err
		}

		tokenType, tokenString = c.getTokenInfo(request)
		if len(tokenType) == 0 && len(tokenString) == 0 {
			return c.responseOKWithoutHeader(), nil
		}
		if tokenType == "basic" || tokenType == "Basic" {
			return c.responseOKWithoutHeader(), nil
		}
	}

	header, err := c.createHeaderFromJWTToken(tokenString)
	if err != nil {
		if _, ok := err.(*jwt.ValidationError); ok {
			return c.responseUnauthorizedError(err), err
		}
		return c.responseInternelServerError(err), err
	}
	return c.responseOKWithHeader(header), nil
}

func (c *checkService) isAvailableCookie(request *Request) bool {
	accessToken, err := request.Request.Cookie("accessToken")
	if err != nil || accessToken == nil {
		return false
	}
	return true
}

func (c *checkService) getAccessTokenFromCookie(request *Request) string {
	accessToken, err := request.Request.Cookie("accessToken")
	if err != nil || accessToken == nil {
		return ""
	} else {
		return accessToken.Value
	}
}

func (c *checkService) findNotAvailableHeader(request *Request) []string {
	blackList := []string{"Request-User-Id", "Request-User-Role", "Request-User-Authorities"}
	result := []string{}
	for _, key := range blackList {
		if len(request.Request.Header.Get(key)) != 0 {
			result = append(result, key)
		}
	}

	return result
}

func (c *checkService) getTokenInfo(request *Request) (string, string) {
	token := request.Request.Header.Get("Authorization")
	splittedToken := strings.Split(token, " ")
	if len(splittedToken) != 2 {
		return "", ""
	}
	return splittedToken[0], splittedToken[1]
}

func (c *checkService) createHeaderFromJWTToken(jwtToken string) (http.Header, error) {
	var headers = make(http.Header)

	claims, err := ParseJWTToken(jwtToken)
	if err != nil {
		return nil, err
	}

	headers.Add("Request-User-Id", claims.Subject)
	headers.Add("Request-User-Role", claims.Role)
	headers.Add("Request-User-Authorities", strings.Join(claims.Authorities, " "))
	// for _, v := range claims.Authorities {
	// 	headers.Add("Request-User-Authorities", v)
	// }
	headers.Add("Request-Id", c.getRequestId())

	return headers, nil
}

func (c *checkService) getRequestId() string {
	return uuid.NewString()
}

func (c *checkService) responseInternelServerError(err error) *Response {
	c.log.Error(err, 500)
	defer sentry.Flush(2 * time.Second)
	sentry.CaptureException(err)
	return &Response{
		Allow: false,
		Response: http.Response{
			StatusCode: http.StatusInternalServerError,
		},
	}
}

func (c *checkService) responseUnauthorizedError(err error) *Response {
	c.log.Info(err, 401)
	defer sentry.Flush(2 * time.Second)
	sentry.CaptureException(err)
	return &Response{
		Allow: false,
		Response: http.Response{
			StatusCode: http.StatusUnauthorized,
		},
	}
}

func (c *checkService) responseOKWithoutHeader() *Response {
	return &Response{
		Allow: true,
		Response: http.Response{
			StatusCode: http.StatusOK,
		},
	}
}

func (c *checkService) responseOKWithHeader(header http.Header) *Response {
	c.log.Info("response with header: ", header)
	defer sentry.Flush(2 * time.Second)
	sentry.CaptureMessage(fmt.Sprintf("response with header: %v", header))
	response := &Response{
		Allow: true,
		Response: http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
		},
	}

	for key, values := range header {
		for i := 0; i < len(values); i++ {
			response.Response.Header.Add(key, values[i])
		}
	}

	return response
}

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

func (s *extAuthzServerV2) logRequest(allow string, request *envoy_service_auth_v2.CheckRequest) {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	log.Printf("[gRPCv2][%s]: %s%s, attributes: %v\n", allow, httpAttrs.GetHost(),
		httpAttrs.GetPath(),
		request.GetAttributes())
}

// Check implements gRPC v2 check request.
func (s *extAuthzServerV2) Check(ctx context.Context, checkRequest *envoy_service_auth_v2.CheckRequest) (*envoy_service_auth_v2.CheckResponse, error) {

	s.logRequest("", checkRequest)

	request := Request{}
	request.FromV2(checkRequest)

	response, err := s.checkService.Check(ctx, &request)
	if err != nil {
		return nil, err
	}
	return response.AsV2(), nil
}

func (s *extAuthzServerV3) logRequest(allow string, request *envoy_service_auth_v3.CheckRequest) {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	log.Printf("[gRPCv3][%s]: %s%s, attributes: %v\n", allow, httpAttrs.GetHost(),
		httpAttrs.GetPath(),
		request.GetAttributes())
}

// Check implements gRPC v3 check request.
func (s *extAuthzServerV3) Check(ctx context.Context, checkRequest *envoy_service_auth_v3.CheckRequest) (*envoy_service_auth_v3.CheckResponse, error) {

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
	envoy_service_auth_v2.RegisterAuthorizationServer(s.grpcServer, s.grpcV2)
	envoy_service_auth_v3.RegisterAuthorizationServer(s.grpcServer, s.grpcV3)

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

var (
	grpcPort = flag.String("grpc", "9000", "gRPC server port")
)

func main() {
	flag.Parse()
	s := NewExtAuthzServer()

	go s.Run(fmt.Sprintf(":%s", *grpcPort))
	defer s.Stop()

	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
