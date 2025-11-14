package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GroVlAn/auth-example/internal/config"
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
	defaultConfigPath = "configs/config-example.yml"
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

	s := service.New(repo.Auth(), repo.User(), service.DepsAuthService{
		TokenRefreshEndTTL: cfg.Settings.TokenRefreshEndTTL,
		TokenAccessEndTTL:  cfg.Settings.TokenAccessEndTTL,
		SecretKey:          cfg.Settings.SecretKey,
	}, service.DepsUserService{
		HashCost: cfg.Settings.HashCost,
	})

	h := httpHandler.New(l, s.User(), s.Auth(), httpHandler.Deps{
		BasePath:       cfg.HTTP.BaseHTTPPath,
		DefaultTimeout: cfg.Settings.DefaultTimeout,
	})
	gh := grpcHandler.New(l, s.User(), s.Auth(), grpcHandler.Deps{
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
