FROM golang:1.10-alpine3.8 as builder
RUN apk update && apk add git
ADD *.go /go/src/ambassador-auth/
WORKDIR /go/src/ambassador-auth
ADD Gopkg.toml .
ADD Gopkg.lock .
RUN go get github.com/golang/dep/cmd/dep
RUN dep ensure
RUN go build -o /go/bin/ambassador-auth

FROM alpine:3.8
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
RUN addgroup -S auth && adduser -S -G auth auth
USER auth
WORKDIR /app
COPY --from=builder /go/bin/ambassador-auth /app/
ENTRYPOINT [ "./ambassador-auth" ]
