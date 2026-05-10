# eBPF Security Monitor

基于 eBPF 的轻量级主机安全监控系统，实时采集进程、网络、文件三类内核事件，支持容器环境识别，提供 Web 实时展示与事件过滤能力。

## 功能特性

### 进程事件监控
- 进程创建 (fork)
- 进程执行 (execve)
- 进程退出 (exit)
- 权限提升检测 (privilege escalation)

### 网络事件监控
- TCP 连接建立/关闭
- TCP 连接状态变化
- UDP 数据包发送/接收
- IPv4/IPv6 支持

### 文件事件监控
- 文件创建
- 文件修改
- 文件删除
- 文件重命名
- 权限修改 (chmod)
- 所有者修改 (chown)

### 其他特性
- 支持主机和容器场景
- 实时 WebSocket 事件推送
- Web 界面实时展示
- 事件过滤和搜索
- JSON 格式导出

## 系统要求

- Linux 内核版本 >= 5.8
- Go >= 1.21
- Clang/LLVM >= 11
- libbpf >= 0.5
- root 权限运行

## 安装

### 从源码构建

```bash
# 克隆项目
git clone <repository-url>
cd ebpf-by-glm5

# 安装依赖
sudo apt-get install -y clang llvm gcc libbpf-dev linux-headers-generic

# 构建
make build

# 运行
sudo make run
```

### 使用 Docker

```bash
# 构建镜像
make docker-build

# 运行容器
make docker-run
```

## 使用方法

### 启动监控

```bash
sudo ./output/ebpf-monitor
```

### 访问 Web 界面

打开浏览器访问 `http://localhost:8080`

### 界面功能

1. **实时事件显示**: 通过 WebSocket 实时推送事件
2. **事件过滤**: 按类型（进程/网络/文件）过滤
3. **进程搜索**: 搜索特定进程名称
4. **PID 过滤**: 过滤特定 PID 的事件
5. **容器过滤**: 显示主机或容器事件
6. **暂停/恢复**: 控制事件流
7. **清除**: 清除所有显示的事件
8. **导出**: 导出为 JSON 文件

## 配置

### 端口配置

默认端口: `8080`

修改端口:
```go
srv := server.NewServer(":9090", eventChan)
```

### 事件缓冲区大小

在 BPF 代码中调整:
```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB
} process_events SEC(".maps");
```

### 最大显示事件数

在前端界面中调整，默认 500。

## 事件类型

| 类型 | 名称 | 描述 |
|------|------|------|
| 0 | fork | 进程创建 |
| 1 | exec | 进程执行新程序 |
| 2 | exit | 进程退出 |
| 3 | privilege | 权限提升 |
| 4 | connect | TCP 连接 |
| 5 | accept | TCP 接受连接 |
| 6 | close | TCP 关闭 |
| 7 | udp_send | UDP 发送 |
| 8 | udp_recv | UDP 接收 |
| 9 | create | 文件创建 |
| 10 | modify | 文件修改 |
| 11 | delete | 文件删除 |
| 12 | rename | 文件重命名 |
| 13 | chmod | 权限修改 |
| 14 | chown | 所有者修改 |

## 容器识别

系统通过以下方式识别容器:
- 读取 `/proc/<pid>/cgroup` 文件
- 检测 docker/containerd 标识
- 识别 kubepods 环境

## 安全注意事项

- 需要 root 权限运行
- BPF 程序会读取系统敏感信息
- 在生产环境使用前请进行安全评估
- 建议使用最小权限原则

## 常见问题

### Q: 无法加载 BPF 程序
A: 检查内核版本和 BTF 支持，确保内核 >= 5.8

### Q: 权限错误
A: 确保以 root 用户运行

### Q: Web 界面无法访问
A: 检查防火墙设置和端口占用

### Q: 事件显示不完整
A: 可能是事件缓冲区溢出，调整缓冲区大小

## 开发

### 添加新的事件类型

1. 在 `bpf/common.h` 中定义新类型
2. 实现相应的 BPF 程序
3. 更新用户态解析代码
4. 更新前端显示

### 调试 BPF 程序

```bash
# 查看 BPF 程序状态
sudo bpftool prog list

# 查看 BPF map 状态
sudo bpftool map list

# 追踪 BPF 程序
sudo bpftool prog tracelog
```

## 贡献

欢迎提交 Issue 和 Pull Request。

## 许可证

GPL-2.0

## 参考资料

- [eBPF 官方文档](https://ebpf.io/)
- [Cilium eBPF 库](https://github.com/cilium/ebpf)
- [Linux 内核 BPF 文档](https://www.kernel.org/doc/html/latest/bpf/index.html)