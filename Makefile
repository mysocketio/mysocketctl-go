GOCMD=go
GOBUILD=$(GOCMD) build
GOFMT=$(GOCMD)fmt
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=mysocketctl
BUCKET=pub-mysocketctl-bin

DATE := $(shell git log -1 --format=%cd --date=format:"%Y%m%d")
VERSION := $(shell git describe --long --dirty --tags)
FLAGS := -ldflags "-X github.com/mysocketio/mysocketctl-go/cmd.version=$(VERSION) -X github.com/mysocketio/mysocketctl-go/cmd.date=$(DATE)"

all: lint moddownload test build

release:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(FLAGS) -o ./bin/$(BINARY_NAME)_windows_amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(FLAGS) -o ./bin/$(BINARY_NAME)_linux_amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(FLAGS) -o ./bin/$(BINARY_NAME)_linux_arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm go build $(FLAGS) -o ./bin/$(BINARY_NAME)_linux_arm
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(FLAGS)  -o ./bin/$(BINARY_NAME)_darwin_amd64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(FLAGS)  -o ./bin/$(BINARY_NAME)_darwin_arm64

	shasum -a 256 ./bin/mysocketctl_darwin_amd64 | awk '{print $$1}' > ./bin/mysocketctl_darwin_amd64-sha256-checksum.txt
	python3 ./s3upload.py ./bin/mysocketctl_darwin_amd64-sha256-checksum.txt ${BUCKET} darwin_amd64/sha256-checksum.txt
	python3 ./s3upload.py ./bin/mysocketctl_darwin_amd64 ${BUCKET} darwin_amd64/mysocketctl

	shasum -a 256 ./bin/mysocketctl_darwin_arm64 | awk '{print $$1}' > ./bin/mysocketctl_darwin_arm64-sha256-checksum.txt
	python3 ./s3upload.py ./bin/mysocketctl_darwin_arm64-sha256-checksum.txt ${BUCKET} darwin_arm64/sha256-checksum.txt
	python3 ./s3upload.py ./bin/mysocketctl_darwin_arm64 ${BUCKET} darwin_arm64/mysocketctl

	shasum -a 256 ./bin/mysocketctl_linux_amd64 | awk '{print $$1}' > ./bin/mysocketctl_linux_amd64-sha256-checksum.txt
	python3 ./s3upload.py ./bin/mysocketctl_linux_amd64-sha256-checksum.txt ${BUCKET} linux_amd64/sha256-checksum.txt
	python3 ./s3upload.py ./bin/mysocketctl_linux_amd64 ${BUCKET} linux_amd64/mysocketctl

	#This is for Raspberrypi
	shasum -a 256 ./bin/mysocketctl_linux_arm64 | awk '{print $$1}' > ./bin/mysocketctl_linux_arm64-sha256-checksum.txt
	python3 ./s3upload.py ./bin/mysocketctl_linux_arm64-sha256-checksum.txt ${BUCKET} linux_arm64/sha256-checksum.txt
	python3 ./s3upload.py ./bin/mysocketctl_linux_arm64 ${BUCKET} linux_arm64/mysocketctl

	#This is for Raspberrypi 32bit
	shasum -a 256 ./bin/mysocketctl_linux_arm | awk '{print $$1}' > ./bin/mysocketctl_linux_arm-sha256-checksum.txt
	python3 ./s3upload.py ./bin/mysocketctl_linux_arm-sha256-checksum.txt ${BUCKET} linux_arm/sha256-checksum.txt
	python3 ./s3upload.py ./bin/mysocketctl_linux_arm ${BUCKET} linux_arm/mysocketctl

	shasum -a 256 ./bin/mysocketctl_windows_amd64 | awk '{print $$1}' > ./bin/mysocketctl_windows_amd64-sha256-checksum.txt
	python3 ./s3upload.py ./bin/mysocketctl_windows_amd64-sha256-checksum.txt ${BUCKET} windows_amd64/sha256-checksum.txt
	python3 ./s3upload.py ./bin/mysocketctl_windows_amd64 ${BUCKET} windows_amd64/mysocketctl.exe

	echo ${VERSION} > latest_version.txt
	python3 ./s3upload.py latest_version.txt ${BUCKET} latest_version.txt
	rm latest_version.txt

release-border0:
	python3 ./s3upload.py ./bin/mysocketctl_darwin_amd64 ${BUCKET} darwin_amd64/border0
	python3 ./s3upload.py ./bin/mysocketctl_darwin_arm64 ${BUCKET} darwin_arm64/border0
	python3 ./s3upload.py ./bin/mysocketctl_linux_amd64 ${BUCKET} linux_amd64/border0

	#This is for Raspberrypi
	python3 ./s3upload.py ./bin/mysocketctl_linux_arm64 ${BUCKET} linux_arm64/border0

	#This is for Raspberrypi 32bit
	python3 ./s3upload.py ./bin/mysocketctl_linux_arm ${BUCKET} linux_arm/border0
	python3 ./s3upload.py ./bin/mysocketctl_windows_amd64 ${BUCKET} windows_amd64/border0.exe

moddownload:
	go mod tidy
	go mod download

build:
	$(GOBUILD) $(FLAGS) -o $(BINARY_NAME) -v

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(FLAGS) -o $(BINARY_NAME) -v

build-all:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(FLAGS) -o $(BINARY_NAME)_windows_amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(FLAGS) -o $(BINARY_NAME)_linux_amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(FLAGS) -o $(BINARY_NAME)_linux_arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm go build $(FLAGS) -o $(BINARY_NAME)_linux_arm
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(FLAGS)  -o $(BINARY_NAME)_darwin_amd64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(FLAGS)  -o $(BINARY_NAME)_darwin_arm64

lint:
	@echo "running go fmt"
	$(GOFMT) -w .

test:
	$(GOTEST) -v ./...
	$(GOCMD) run ./main.go version check

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)

run:
	$(GOBUILD) $(FLAGS) -o $(BINARY_NAME) -v ./...
	./$(BINARY_NAME)

