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
	httpHandler "github.com/GroVlAn/auth-example/internal/handler/http"
	"github.com/GroVlAn/auth-example/internal/repository"
	"github.com/GroVlAn/auth-example/internal/server"
	"github.com/GroVlAn/auth-example/internal/service"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
)

const (
	defaultConfigPath = "configs/config-dev.yaml"
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

	server := server.New(
		h.Handler(),
		server.Settings{
			Port:              cfg.HTTP.Port,
			MaxHeaderBytes:    cfg.HTTP.MaxHeaderBytes,
			ReadHeaderTimeout: time.Duration(cfg.HTTP.ReadHeaderTimeout) * time.Second,
			WriteTimeout:      time.Duration(cfg.HTTP.WriteTimeout) * time.Second,
		},
	)

	go func() {
		if err := server.Strart(); err != nil && err != http.ErrServerClosed {
			l.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	l.Info().Msgf("server start on port: %s load time: %v", cfg.HTTP.Port, time.Since(timeStart))

	<-ctx.Done()
	err = server.Shutdown(ctx)
	if err != nil {
		l.Fatal().Err(err).Msg("failed to shutdown server")
	} else {
		l.Info().Msg("server shutdown gracefully")
	}
}
