package grpc_server

import (
	"fmt"
	"net"

	"github.com/GroVlAn/auth-example/api/auth"
	"github.com/GroVlAn/auth-example/api/user"
	"google.golang.org/grpc"
)

type Deps struct {
	UserService user.UserServiceServer
	AuthService auth.AuthServiceServer
}

type Server struct {
	srv *grpc.Server
	Deps
}

func New(deps Deps) *Server {
	return &Server{
		srv:  grpc.NewServer(),
		Deps: deps,
	}
}

func (s *Server) ListenAndServe(port string) error {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("failed listen tcp server: %w", err)
	}

	user.RegisterUserServiceServer(s.srv, s.Deps.UserService)
	auth.RegisterAuthServiceServer(s.srv, s.Deps.AuthService)

	if err = s.srv.Serve(lis); err != nil {
		return fmt.Errorf("failed serve grpc server: %w", err)
	}

	return nil
}

func (s *Server) Stop() {
	s.srv.GracefulStop()
}
