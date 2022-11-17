# Setup
```sh
$ go mod init envoy-xds-server
$ go get -u github.com/go-sql-driver/mysql
$ go mod tidy

# for hello world
$ go run ./cmd/hello-world/main.go
$ go build -o ./bin/hello-world ./cmd/hello-world/main.go

# for envoy-xds-server
$ export GOPATH="$PWD"
$ go run ./cmd/envoy-xds-server/main.go
$ go build -o ./bin/envoy-xds-server ./cmd/envoy-xds-server/main.go
$ go build -o ./bin/envoy-xds-server ./internal/example/main/main.go
```

# Make
```sh
make build # build the code
make test # test the code
make vet # check the vetting
make lint # check the linting
make fmt # check the formatting
make # ensure everything passes and builds
```

# golang proxy
```sh
$ export GOPROXY=https://proxy.golang.com.cn,direct
# on mac
$ export GOPROXY=https://proxy.golang.com.cn,direct >> ~/.zshrc && ~/.zshrc
# on linux
$ export GOPROXY=https://proxy.golang.com.cn,direct >> ~/.profile && ~/.profile
```