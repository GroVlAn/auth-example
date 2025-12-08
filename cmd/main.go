package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GroVlAn/auth-example/internal/config"
	"github.com/GroVlAn/auth-example/internal/core/e"
	"github.com/GroVlAn/auth-example/internal/database"
	grpcHandler "github.com/GroVlAn/auth-example/internal/handler/grpc"
	httpHandler "github.com/GroVlAn/auth-example/internal/handler/http"
	"github.com/GroVlAn/auth-example/internal/repository"
	grpcServer "github.com/GroVlAn/auth-example/internal/server/grpc-server"
	httpServer "github.com/GroVlAn/auth-example/internal/server/http-server"
	"github.com/GroVlAn/auth-example/internal/service"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
)

const (
	defaultConfigPath     = "configs/config-example.yml"
	defaultRoleConfigPath = "configs/role-config.json"
)

func main() {
	timeStart := time.Now()

	l := zerolog.New(os.Stdout).
		With().
		Timestamp().
		Logger().
		Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "2006-01-02 15:04:05"})

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := config.LoadEnv(); err != nil {
		l.Fatal().Err(err).Msg("failed to load env variables")
	}

	configPath := flag.String("config", defaultConfigPath, "Path to the configuration file")
	roleConfigPath := flag.String("role-config", defaultRoleConfigPath, "Path to the configuration file")
	flag.Parse()

	cfg, err := config.New(*configPath)
	if err != nil {
		l.Fatal().Err(err).Msg("failed to load configuration")
	}

	db, err := database.NewPostgresqlDB(database.PostgresSettings{
		Host:     cfg.DB.Host,
		Port:     cfg.DB.Port,
		Username: cfg.DB.Username,
		Password: cfg.DB.Password,
		DBName:   cfg.DB.DBName,
		SSLMode:  cfg.DB.SSLMode,
	})
	if err != nil {
		l.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer func() {
		if err := db.Close(); err != nil {
			l.Error().Err(err).Msg("failed to close database connection")
		}
	}()

	repo := repository.New(db)

	preloader := service.NewRoleLoader(repo.Role(), repo.User(), service.PreloaderDeps{
		DefRolePath: *roleConfigPath,
		HashCost:    cfg.Settings.HashCost,
	})

	s := service.New(
		service.Repositories{
			AuthRepo: repo.Auth(),
			UserRepo: repo.User(),
			RoleRepo: repo.Role(),
		},
		cfg.Settings.SecretKey,
		service.DepsAuthService{
			TokenRefreshEndTTL: cfg.Settings.TokenRefreshEndTTL,
			TokenAccessEndTTL:  cfg.Settings.TokenAccessEndTTL,
		}, service.DepsUserService{
			HashCost: cfg.Settings.HashCost,
		})

	h := httpHandler.New(
		l,
		httpHandler.Services{
			UserService: s.User(),
			AuthService: s.Auth(),
			RoleService: s.Role(),
		},
		httpHandler.Deps{
			BasePath:       cfg.HTTP.BaseHTTPPath,
			DefaultTimeout: cfg.Settings.DefaultTimeout,
		},
	)
	gh := grpcHandler.New(
		l,
		grpcHandler.Services{
			UserService: s.User(),
			AuthService: s.Auth(),
			RoleService: s.Role(),
		},
		grpcHandler.Deps{
			DefaultTimeout: cfg.Settings.DefaultTimeout,
		})

	hServer := httpServer.New(
		h.Handler(),
		httpServer.Settings{
			Port:              cfg.HTTP.Port,
			MaxHeaderBytes:    cfg.HTTP.MaxHeaderBytes,
			ReadHeaderTimeout: time.Duration(cfg.HTTP.ReadHeaderTimeout) * time.Second,
			WriteTimeout:      time.Duration(cfg.HTTP.WriteTimeout) * time.Second,
		},
	)

	gServer := grpcServer.New(
		grpcServer.Deps{
			UserService: gh,
			RoleService: gh,
			AuthService: gh,
		},
	)

	go func() {
		if err := hServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			l.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	go func() {
		l.Info().Msgf("grpc server started on port: %s", cfg.GRPC.Port)

		if err := gServer.ListenAndServe(cfg.GRPC.Port); err != nil {
			l.Fatal().Err(err).Msg("failed to start grpc server")
		}
	}()

	go func() {
		loadDefaultRoles(ctx, l, cfg, preloader)
		createSuperuser(ctx, l, cfg, preloader)
	}()

	l.Info().Msgf("server start on port: %s load time: %v", cfg.HTTP.Port, time.Since(timeStart))

	<-ctx.Done()
	err = hServer.Shutdown(ctx)
	if err != nil {
		l.Fatal().Err(err).Msg("failed to shutdown server")
	} else {
		l.Info().Msg("server shutdown gracefully")
	}
	gServer.Stop()
}

func loadDefaultRoles(ctx context.Context, l zerolog.Logger, cfg *config.Config, preloader *service.Preloader) {
	ctxR, cancelR := context.WithTimeout(ctx, cfg.Settings.DefaultTimeout)
	defer cancelR()

	err := preloader.CreateDefaultRoles(ctxR)

	var errWrapper *e.ErrWrapper
	if errors.As(err, &errWrapper) {
		switch errWrapper.ErrorType() {
		case e.ErrorTypeInternal:
			l.Fatal().Err(errWrapper.Unwrap()).Msg(errWrapper.Error())
		default:
			l.Fatal().Err(err).Msg("failed create default roles")
		}
	} else if err != nil {
		l.Fatal().Err(err).Msg("failed create default roles")
	}
}

func createSuperuser(ctx context.Context, l zerolog.Logger, cfg *config.Config, preloader *service.Preloader) {
	ctxR, cancelR := context.WithTimeout(ctx, cfg.Settings.DefaultTimeout)
	defer cancelR()

	err := preloader.CreateSuperuser(ctxR, cfg.Superuser)
	var errWrapper *e.ErrWrapper
	var errValidation *e.ErrValidation
	if errors.As(err, &errValidation) {
		field, reason, ok := errValidation.FirstError()
		if ok {
			l.Error().Err(err).Msgf("failed validate superuser: field: %s reason: %s", field, reason)
		}
	}

	if errors.As(err, &errWrapper) {
		switch errWrapper.ErrorType() {
		case e.ErrorTypeInternal:
			l.Fatal().Err(errWrapper.Unwrap()).Msg(errWrapper.Error())
		default:
			l.Fatal().Err(err).Msg("failed create superuser")
		}
	} else if err != nil {
		l.Fatal().Err(err).Msg("failed create superuser")
	}
}
