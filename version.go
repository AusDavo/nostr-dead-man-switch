package main

// version is the build-time release tag. The release Dockerfile and CI
// workflow override this via `-ldflags "-X main.version=<tag>"`. Local
// `go build` leaves it as "dev".
var version = "dev"
