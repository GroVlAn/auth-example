package cron

import (
	"context"
	"fmt"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/rs/zerolog"
)

type service interface {
	DeleteInactiveUser(ctx context.Context) error
}

type Cron struct {
	s       gocron.Scheduler
	service service
	l       zerolog.Logger
}

func New(l zerolog.Logger, service service) (*Cron, error) {
	s, err := gocron.NewScheduler()
	if err != nil {
		return nil, fmt.Errorf("creating cron scheduler: %w", err)
	}

	return &Cron{
		s:       s,
		service: service,
		l:       l,
	}, nil
}

func (c *Cron) DeleteInactiveUser(ctx context.Context, durJob time.Duration, timeout time.Duration) error {
	j, err := c.s.NewJob(
		gocron.DurationJob(
			durJob,
		),
		gocron.NewTask(
			func() {
				ctx, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()

				if err := c.service.DeleteInactiveUser(ctx); err != nil {
					c.l.Error().Err(err).Msg("failed delete inactive users")
				}
			},
		),
	)

	if err != nil {
		return fmt.Errorf("creating cron job: %w", err)
	}

	c.l.Info().Msgf("start cron job with ID: %s", j.ID())

	return nil
}

func (c *Cron) Start() {
	c.s.Start()
}

func (c *Cron) Shutdown() error {
	if err := c.s.Shutdown(); err != nil {
		return fmt.Errorf("stopping cron: %w", err)
	}

	return nil
}
