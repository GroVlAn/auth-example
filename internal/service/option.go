package service

type Option func(*Service)

func WithRepositories(reps Repositories) Option {
	return func(srv *Service) {
		srv.Repositories = reps
	}
}

func WithCache(cache Cache) Option {
	return func(srv *Service) {
		srv.cache = cache
	}
}

func WithAuthDeps(authDeps AuthDeps) Option {
	return func(srv *Service) {
		srv.authDeps = authDeps
	}
}

func WithUserDeps(userDeps UserDeps) Option {
	return func(srv *Service) {
		srv.userDeps = userDeps
	}
}

func WithRoleDeps(roleDeps RoleDeps) Option {
	return func(srv *Service) {
		srv.roleDeps = roleDeps
	}
}
