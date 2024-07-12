# 使用 golang 官方镜像作为基础镜像
FROM golang:latest

# 设置工作目录
WORKDIR /go/src/app

# 复制当前目录下的所有文件到容器的 /go/src/app 目录中
COPY . .

# 编译可执行文件
RUN go build -o dns-server .

# 声明容器提供的端口号
EXPOSE 53/tcp
EXPOSE 53/udp

# 运行可执行文件
CMD ["./dns-server"]

