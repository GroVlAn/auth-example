package http_handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	"github.com/go-chi/chi"
	"github.com/rs/zerolog"
)

type authenticator interface {
	Authenticate(ctx context.Context, authUser core.AuthUser, userAgent string) (core.RefreshToken, core.AccessToken, error)
	UpdateAccessToken(ctx context.Context, rfToken string) (core.AccessToken, error)
	VerifyAccessToken(ctx context.Context, accToken string) error
	Logout(ctx context.Context, refreshToken, accessToken string) error
	LogoutAllDevices(ctx context.Context, userID string) error
	LogoutDeviceByUserAgent(ctx context.Context, userID, userAgent string) error
}

type userService interface {
	CreateUser(ctx context.Context, user core.User) error
	User(ctx context.Context, userReq core.UserRequest) (core.User, error)
}

type Deps struct {
	BasePath       string
	DefaultTimeout time.Duration
}

type HTTPHandler struct {
	l           zerolog.Logger
	userService userService
	authService authenticator
	Deps
}

func New(l zerolog.Logger, userService userService, authService authenticator, deps Deps) *HTTPHandler {
	return &HTTPHandler{
		l:           l,
		userService: userService,
		authService: authService,
		Deps:        deps,
	}
}

func (h *HTTPHandler) Handler() *chi.Mux {
	r := chi.NewRouter()

	h.useMiddleware(r)

	r.Route("/", func(r chi.Router) {
		r.Get("/home", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Welcome to the Home Page!"))
		})
	})

	r.Route(h.BasePath, func(r chi.Router) {
		h.userRoute(r)
		h.authRoute(r)
	})

	return r
}

func (h *HTTPHandler) useMiddleware(r *chi.Mux) {
	r.Use(h.Cors)
}

func (h *HTTPHandler) sendResponse(w http.ResponseWriter, res core.Response, status int) {
	b, err := json.Marshal(res)
	if err != nil {
		h.l.Error().Err(err).Msg("failed marshal response")
	}

	w.WriteHeader(status)

	_, err = w.Write(b)
	if err != nil {
		h.l.Error().Err(err).Msg("failed write response")
	}
}

func (h *HTTPHandler) handleError(err error) (int, core.Response) {
	var errValidation *e.ErrValidation
	var errWrapper *e.ErrWrapper

	if errors.As(err, &errValidation) {
		return h.handleValidationError(err, errValidation)
	}

	if errors.As(err, &errWrapper) {
		return h.handleErrorWrapper(errWrapper)
	}

	return http.StatusInternalServerError, core.Response{
		Error: &core.ErrorResponse{
			Code: http.StatusInternalServerError,
			Text: "internal server error",
		},
	}
}

func (h *HTTPHandler) handleDecodeBody(w http.ResponseWriter, err error) {
	ev := e.NewErrValidation("failed read request body")

	switch e := err.(type) {
	case *json.SyntaxError:
		ev.AddField("body", fmt.Sprintf("invalid JSON syntax at offset %d", e.Offset))
	case *json.UnmarshalTypeError:
		ev.AddField(e.Field, fmt.Sprintf("expected %v but got %v", e.Type, e.Value))
	default:
		if errors.Is(err, io.EOF) {
			ev.AddField("body", "empty request body")
		} else {
			ev.AddField("body", err.Error())
		}
	}

	h.l.Error().Err(err).Msg("failed to decode request body")

	status, res := h.handleError(ev)
	h.sendResponse(w, res, status)
}

func (h *HTTPHandler) handleValidationError(err error, errValidation *e.ErrValidation) (int, core.Response) {
	h.l.Error().Err(err).Msg("validation error occurred")

	data := errValidation.Data()

	return http.StatusBadRequest, core.Response{
		Error: &core.ErrorResponse{
			Code: http.StatusBadRequest,
			Text: errValidation.Error(),
		},
		Data: data,
	}
}

func (h *HTTPHandler) handleErrorWrapper(errWrapper *e.ErrWrapper) (int, core.Response) {
	switch errWrapper.ErrorType() {
	case e.ErrorTypeNotFound:
		h.l.Error().Err(errWrapper.Unwrap()).Msg("error not found occurred")

		return http.StatusNotFound, core.Response{
			Error: &core.ErrorResponse{
				Code: http.StatusNotFound,
				Text: errWrapper.Error(),
			},
		}
	case e.ErrorTypeConflict:
		h.l.Error().Err(errWrapper.Unwrap()).Msg("error conflict occurred")

		return http.StatusConflict, core.Response{
			Error: &core.ErrorResponse{
				Code: http.StatusConflict,
				Text: errWrapper.Error(),
			},
		}
	case e.ErrorTypeUnauthorized:
		h.l.Error().Err(errWrapper.Unwrap()).Msg("error unauthorized occurred")

		return http.StatusUnauthorized, core.Response{
			Error: &core.ErrorResponse{
				Code: http.StatusUnauthorized,
				Text: errWrapper.Error(),
			},
		}
	case e.ErrorTypeInternal:
		h.l.Error().Err(errWrapper.Unwrap()).Msg("error internal occurred")

		return http.StatusInternalServerError, core.Response{
			Error: &core.ErrorResponse{
				Code: http.StatusInternalServerError,
				Text: errWrapper.Error(),
			},
		}
	default:
		h.l.Error().Err(errWrapper.Unwrap()).Msg("error internal(not wrapped) occurred")

		return http.StatusInternalServerError, core.Response{
			Error: &core.ErrorResponse{
				Code: http.StatusInternalServerError,
				Text: "internal server error",
			},
		}
	}
}
