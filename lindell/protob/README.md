//go:generate sh -c "rm -f ./pb/*pb.go; protoc --proto_path=$GOPATH/src:. --go_out=. *.proto"
