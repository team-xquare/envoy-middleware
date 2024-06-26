package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/xquare-team/envoy-middleware-test/pkg/errors"
	"github.com/xquare-team/envoy-middleware-test/pkg/jwt"
)

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

        if request.Request.Header.Get("X-Not-Using-Xquare-Auth") != "" {
		return c.responseOKWithoutHeader(), nil
	}
	
	if request.Request.Method == "OPTIONS" {
		return c.responseOKWithoutHeader(), nil
	}
	
	var tokenString string
	var tokenType string

	if request.Request.Header.Get("X-Is-Not-Xquare-Auth") != "" || request.Request.Method == "OPTIONS" {
		return c.responseOKWithoutHeader(), nil
	}

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
			return c.responseOKWithoutHeader(), nil
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
	blackList := []string{"Request-User-Authorities"}
	result := []string{}
	for _, key := range blackList {
		if len(request.Request.Header.Get(key)) != 0 {
			result = append(result, key)
		}
	}

	return result
}

func (c *checkService) getTokenInfo(request *Request) (string, string) {
	token := request.Request.Header.Get("authorization")
	splittedToken := strings.Split(token, " ")
	if len(splittedToken) != 2 {
		return "", ""
	}
	return splittedToken[0], splittedToken[1]
}

func (c *checkService) createHeaderFromJWTToken(jwtToken string) (http.Header, error) {
	var headers = make(http.Header)

	claims, err := jwt.ParseJWTToken(jwtToken)
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
