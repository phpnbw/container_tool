FROM golang:1.23-alpine AS builder
WORKDIR /app
ENV GOPROXY=https://goproxy.cn,direct
ENV GO111MODULE=on
COPY go.mod go.sum* ./
RUN go mod tidy
COPY .. .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o main .

# 使用轻量级的alpine作为最终镜像
FROM alpine:3.18
WORKDIR /app
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk --no-cache add ca-certificates tzdata docker-cli && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone
COPY --from=builder /app/main .
COPY static static/
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/api/test || exit 1
CMD ["./main"] 