FROM golang:1.17.3

WORKDIR /go/src/app
COPY go.mod .
COPY go.sum .
RUN go mod download

COPY *.go ./
COPY env.yaml .

RUN go build -o /api-server

EXPOSE 6060

CMD ["/api-server"]