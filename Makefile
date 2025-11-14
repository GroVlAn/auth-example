.PHONY:

.DEFAULT_GOAL := gen

gen:
	protoc -I=api/proto --go_out=api/ --go_opt=paths=import \
	--go-grpc_out=api/ --go-grpc_opt=paths=import \
	api/proto/user.proto api/proto/auth.proto