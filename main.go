package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// FileNode 表示容器中的文件或目录
type FileNode struct {
	Name        string     `json:"name"`
	Path        string     `json:"path"`
	ContainerId string     `json:"containerId"`
	Children    []FileNode `json:"children,omitempty"`
	Type        string     `json:"type,omitempty"` // 文件类型: "file", "directory", "symlink"
}

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type LoginRequest struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type SSHClient struct {
	client *ssh.Client
	config *ssh.ClientConfig
}

var (
	sshClient *SSHClient
	mu        sync.Mutex
)

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // 允许所有源
	},
}

func main() {
	r := gin.Default()

	r.Use(cors.Default())
	r.Static("/static", "./static")

	api := r.Group("/api")
	{
		api.POST("/login", handleLogin)
		api.GET("/containers", getContainers)
		api.GET("/container/:id/files", getContainerFiles)
		api.GET("/container/:id/file", getFileContent)
		api.POST("/container/:id/file", saveFileContent)
		api.POST("/container/:id/upload", uploadFile)
		api.GET("/container/:id/download", downloadFile)
		api.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"message": "API正常工作",
				"time":    time.Now().Format(time.RFC3339),
			})
		})
		api.GET("/terminal/:id", handleTerminal)
		api.GET("/host-terminal", handleHostTerminal)
	}

	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/static/index.html")
	})

	r.Run(":8080")
}

func handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Success: false,
			Message: "无效的请求数据",
		})
		return
	}

	config := &ssh.ClientConfig{
		User: req.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(req.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", req.Host, req.Port), config)
	if err != nil {
		c.JSON(http.StatusUnauthorized, Response{
			Success: false,
			Message: "SSH连接失败: " + err.Error(),
		})
		return
	}

	mu.Lock()
	if sshClient != nil {
		sshClient.client.Close()
	}
	sshClient = &SSHClient{
		client: client,
		config: config,
	}
	mu.Unlock()

	c.JSON(http.StatusOK, Response{
		Success: true,
		Message: "登录成功",
	})
}

func getContainers(c *gin.Context) {
	if sshClient == nil {
		c.JSON(http.StatusUnauthorized, Response{
			Success: false,
			Message: "未登录",
		})
		return
	}

	session, err := sshClient.client.NewSession()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "创建SSH会话失败: " + err.Error(),
		})
		return
	}
	defer session.Close()

	output, err := session.Output("docker ps --format '{{.ID}}\t{{.Names}}\t{{.Image}}'")
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "获取容器列表失败: " + err.Error(),
		})
		return
	}

	var containers []FileNode
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) >= 2 {
			containers = append(containers, FileNode{
				Name:        fmt.Sprintf("%s (%s)", parts[1], parts[2]),
				ContainerId: parts[0],
			})
		}
	}

	c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    containers,
	})
}

func getContainerFiles(c *gin.Context) {
	containerID := c.Param("id")
	if sshClient == nil {
		c.JSON(http.StatusUnauthorized, Response{
			Success: false,
			Message: "未登录",
		})
		return
	}

	session, err := sshClient.client.NewSession()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "创建SSH会话失败: " + err.Error(),
		})
		return
	}
	defer session.Close()

	// 获取容器内的根目录内容
	cmd := fmt.Sprintf("docker exec %s ls -la / | grep -v '^total' | tail -n +3", containerID)
	output, err := session.Output(cmd)
	if err != nil {
		// 如果ls -la失败，尝试find命令
		session2, err := sshClient.client.NewSession()
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{
				Success: false,
				Message: "创建SSH会话失败: " + err.Error(),
			})
			return
		}
		defer session2.Close()

		cmd := fmt.Sprintf("docker exec %s find / -mindepth 1 -maxdepth 1 -printf '%%P|%%y\\n'", containerID)
		output, err = session2.Output(cmd)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{
				Success: false,
				Message: "获取容器根目录失败: " + err.Error(),
			})
			return
		}

		// 处理find命令的输出
		var files []FileNode
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}

			parts := strings.Split(line, "|")
			if len(parts) != 2 {
				continue
			}

			fileName := parts[0]
			fileType := parts[1]
			filePath := "/" + fileName

			fileNode := FileNode{
				Name:        fileName,
				Path:        filePath,
				ContainerId: containerID,
			}

			// 设置文件类型
			switch fileType {
			case "d":
				fileNode.Type = "directory"
				fileNode.Children = []FileNode{}
			case "f":
				fileNode.Type = "file"
			case "l":
				fileNode.Type = "symlink"
				// 符号链接可能指向目录，稍后可能需要额外处理
			default:
				fileNode.Type = "file" // 默认为文件
			}

			files = append(files, fileNode)
		}

		c.JSON(http.StatusOK, Response{
			Success: true,
			Data:    files,
		})
		return
	}

	// 解析ls -la输出
	var files []FileNode
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		// 分割ls -la输出行
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		// 获取文件名（可能包含空格，取第9个字段到最后）
		fileName := strings.Join(fields[8:], " ")
		// 跳过 . 和 .. 目录
		if fileName == "." || fileName == ".." {
			continue
		}

		// 清理文件名称，去掉箭头部分
		if strings.Contains(fileName, "->") {
			fileName = strings.Split(fileName, "->")[0]
			fileName = strings.TrimSpace(fileName)
		} else if strings.Contains(fileName, "→") {
			fileName = strings.Split(fileName, "→")[0]
			fileName = strings.TrimSpace(fileName)
		}

		// 获取文件类型（从权限字段的第一个字符判断）
		fileType := fields[0][0]
		filePath := "/" + fileName

		fileNode := FileNode{
			Name:        fileName,
			Path:        filePath,
			ContainerId: containerID,
		}

		// 根据文件类型设置节点类型和子节点
		switch fileType {
		case 'd':
			fileNode.Type = "directory"
			fileNode.Children = []FileNode{}
		case '-':
			fileNode.Type = "file"
		case 'l':
			fileNode.Type = "symlink"
			// 符号链接需要额外检查它是否指向目录
			// 稍后可能会更新为目录类型
		default:
			fileNode.Type = "file" // 默认为文件
		}

		files = append(files, fileNode)
	}

	c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    files,
	})
}

func getFileContent(c *gin.Context) {
	containerID := c.Param("id")
	filePath := c.Query("path")
	if sshClient == nil {
		c.JSON(http.StatusUnauthorized, Response{
			Success: false,
			Message: "未登录",
		})
		return
	}

	// 预处理路径，去掉箭头符号及后面的内容
	if strings.Contains(filePath, "->") {
		filePath = strings.Split(filePath, "->")[0]
		filePath = strings.TrimSpace(filePath)
	} else if strings.Contains(filePath, "→") {
		filePath = strings.Split(filePath, "→")[0]
		filePath = strings.TrimSpace(filePath)
	}

	// 首先检查路径是文件还是目录
	session1, err := sshClient.client.NewSession()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "创建SSH会话失败: " + err.Error(),
		})
		return
	}

	// 首先检查是否是符号链接
	cmd := fmt.Sprintf("docker exec %s ls -la %s | head -n 1", containerID, filePath)
	output, err := session1.Output(cmd)
	session1.Close()

	isSymlink := false
	symTarget := ""

	// 检查输出的第一个字符是否为'l'（符号链接）
	if err == nil && len(output) > 0 {
		fields := strings.Fields(string(output))
		if len(fields) > 0 && len(fields[0]) > 0 && fields[0][0] == 'l' {
			isSymlink = true

			// 获取符号链接的目标路径
			session1b, err := sshClient.client.NewSession()
			if err == nil {
				defer session1b.Close()
				cmdTarget := fmt.Sprintf("docker exec %s readlink -f %s", containerID, filePath)
				targetOutput, err := session1b.Output(cmdTarget)
				if err == nil {
					symTarget = strings.TrimSpace(string(targetOutput))
				}
			}
		}
	}

	// 使用test命令检查是否为目录（包括符号链接指向的目录）
	session2, err := sshClient.client.NewSession()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "创建SSH会话失败: " + err.Error(),
		})
		return
	}

	// 如果是符号链接并且成功获取了目标路径，则检查目标路径
	pathToCheck := filePath
	if isSymlink && symTarget != "" {
		pathToCheck = symTarget
	}

	cmd = fmt.Sprintf("docker exec %s test -d %s && echo 'isdir' || echo 'isfile'", containerID, pathToCheck)
	output, err = session2.Output(cmd)
	session2.Close()

	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "检查文件类型失败: " + err.Error(),
		})
		return
	}

	isDir := strings.TrimSpace(string(output)) == "isdir"

	// 如果是目录（或者是指向目录的符号链接），返回子目录和文件列表
	if isDir {
		session3, err := sshClient.client.NewSession()
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{
				Success: false,
				Message: "创建SSH会话失败: " + err.Error(),
			})
			return
		}
		defer session3.Close()

		// 使用要检查的路径（可能是符号链接的目标）
		cmd = fmt.Sprintf("docker exec %s ls -la %s | grep -v '^total' | tail -n +3", containerID, pathToCheck)
		output, err = session3.Output(cmd)
		if err != nil {
			// 如果ls -la失败，尝试find命令
			session3b, err := sshClient.client.NewSession()
			if err != nil {
				c.JSON(http.StatusInternalServerError, Response{
					Success: false,
					Message: "创建SSH会话失败: " + err.Error(),
				})
				return
			}
			defer session3b.Close()

			cmd = fmt.Sprintf("docker exec %s find %s -mindepth 1 -maxdepth 1 -printf '%%P|%%y\\n'", containerID, pathToCheck)
			output, err = session3b.Output(cmd)
			if err != nil {
				c.JSON(http.StatusInternalServerError, Response{
					Success: false,
					Message: "读取目录失败: " + err.Error(),
				})
				return
			}

			// 处理find命令的输出
			var children []FileNode
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if line == "" {
					continue
				}

				parts := strings.Split(line, "|")
				if len(parts) != 2 {
					continue
				}

				fileName := parts[0]
				fileType := parts[1]
				childPath := filepath.Join(filePath, fileName) // 用原始路径，而不是符号链接目标

				childNode := FileNode{
					Name:        fileName,
					Path:        childPath,
					ContainerId: containerID,
				}

				// 如果是目录，添加空的子节点数组
				if fileType == "d" {
					childNode.Children = []FileNode{}
					childNode.Type = "directory"
				} else if fileType == "f" {
					childNode.Type = "file"
				} else {
					// 其他类型默认为文件
					childNode.Type = "file"
				}

				children = append(children, childNode)
			}

			c.JSON(http.StatusOK, Response{
				Success: true,
				Data:    children,
			})
			return
		}

		// 解析ls -la输出
		var children []FileNode
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}

			// 分割ls -la输出行
			fields := strings.Fields(line)
			if len(fields) < 9 {
				continue
			}

			// 获取文件名（可能包含空格，取第9个字段到最后）
			fileName := strings.Join(fields[8:], " ")
			// 跳过 . 和 .. 目录
			if fileName == "." || fileName == ".." {
				continue
			}

			// 清理文件名称，去掉箭头部分，只保留实际文件名
			originalFileName := fileName
			if strings.Contains(fileName, "->") {
				fileName = strings.Split(fileName, "->")[0]
				fileName = strings.TrimSpace(fileName)
			} else if strings.Contains(fileName, "→") {
				fileName = strings.Split(fileName, "→")[0]
				fileName = strings.TrimSpace(fileName)
			}

			// 获取文件类型（从权限字段的第一个字符判断）
			fileType := fields[0][0]
			childPath := filepath.Join(filePath, fileName) // 用原始路径

			// 检查子路径是否为符号链接，如果是，获取其指向
			childSymlinkTarget := ""
			if fileType == 'l' {
				// 从原始文件名中提取符号链接目标
				if strings.Contains(originalFileName, "->") {
					parts := strings.Split(originalFileName, "->")
					if len(parts) > 1 {
						childSymlinkTarget = strings.TrimSpace(parts[1])
						// 如果目标路径不是绝对路径，则相对于当前目录
						if !strings.HasPrefix(childSymlinkTarget, "/") {
							if pathToCheck == "/" {
								childSymlinkTarget = "/" + childSymlinkTarget
							} else {
								childSymlinkTarget = pathToCheck + "/" + childSymlinkTarget
							}
						}
					}
				} else if strings.Contains(originalFileName, "→") {
					parts := strings.Split(originalFileName, "→")
					if len(parts) > 1 {
						childSymlinkTarget = strings.TrimSpace(parts[1])
						// 如果目标路径不是绝对路径，则相对于当前目录
						if !strings.HasPrefix(childSymlinkTarget, "/") {
							if pathToCheck == "/" {
								childSymlinkTarget = "/" + childSymlinkTarget
							} else {
								childSymlinkTarget = pathToCheck + "/" + childSymlinkTarget
							}
						}
					}
				}

				// 如果没有从输出解析到目标，尝试使用readlink获取
				if childSymlinkTarget == "" {
					session3c, err := sshClient.client.NewSession()
					if err == nil {
						defer session3c.Close()
						cmdReadlink := fmt.Sprintf("docker exec %s readlink -f %s/%s", containerID, pathToCheck, fileName)
						targetOutput, err := session3c.Output(cmdReadlink)
						if err == nil {
							childSymlinkTarget = strings.TrimSpace(string(targetOutput))
						}
					}
				}

				// 检查符号链接是否指向目录
				if childSymlinkTarget != "" {
					session3d, err := sshClient.client.NewSession()
					if err == nil {
						defer session3d.Close()
						cmdCheckDir := fmt.Sprintf("docker exec %s test -d %s && echo 'isdir' || echo 'isfile'", containerID, childSymlinkTarget)
						testOutput, err := session3d.Output(cmdCheckDir)
						if err == nil && strings.TrimSpace(string(testOutput)) == "isdir" {
							// 是指向目录的符号链接
							fileType = 'd'
						}
					}
				}
			}

			childNode := FileNode{
				Name:        fileName,
				Path:        childPath,
				ContainerId: containerID,
			}

			// 如果是目录('d')或链接('l')但指向目录，添加空的子节点数组
			if fileType == 'd' {
				childNode.Type = "directory"
				childNode.Children = []FileNode{}
			} else if fileType == 'l' {
				childNode.Type = "symlink"
				childNode.Children = []FileNode{} // 符号链接可能指向目录
			} else if fileType == '-' {
				childNode.Type = "file"
			} else {
				childNode.Type = "file" // 默认为文件
			}

			children = append(children, childNode)
		}

		c.JSON(http.StatusOK, Response{
			Success: true,
			Data:    children,
		})
		return
	}

	// 如果是文件，读取文件内容
	session4, err := sshClient.client.NewSession()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "创建SSH会话失败: " + err.Error(),
		})
		return
	}
	defer session4.Close()

	// 如果是符号链接先获取目标路径
	realPath := filePath
	if isSymlink {
		session4b, err := sshClient.client.NewSession()
		if err == nil {
			defer session4b.Close()
			cmd := fmt.Sprintf("docker exec %s readlink -f %s", containerID, filePath)
			output, err := session4b.Output(cmd)
			if err == nil {
				realPath = strings.TrimSpace(string(output))
			}
		}
	}

	// 直接从容器中读取文件内容
	cmd = fmt.Sprintf("docker exec %s cat %s", containerID, realPath)
	output, err = session4.Output(cmd)
	if err != nil {
		// 如果读取失败，尝试以不同方式获取内容
		session5, err := sshClient.client.NewSession()
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{
				Success: false,
				Message: "创建SSH会话失败: " + err.Error(),
			})
			return
		}
		defer session5.Close()

		// 尝试获取符号链接信息
		cmd = fmt.Sprintf("docker exec %s ls -la %s", containerID, filePath)
		output, err = session5.Output(cmd)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{
				Success: false,
				Message: "读取文件失败: " + err.Error(),
			})
			return
		}

		// 返回符号链接的信息作为文件内容
		c.JSON(http.StatusOK, Response{
			Success: true,
			Data:    string(output),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    string(output),
	})
}

func saveFileContent(c *gin.Context) {
	containerID := c.Param("id")
	if sshClient == nil {
		c.JSON(http.StatusUnauthorized, Response{
			Success: false,
			Message: "未登录",
		})
		return
	}

	var request struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Success: false,
			Message: "无效的请求数据",
		})
		return
	}

	session, err := sshClient.client.NewSession()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "创建SSH会话失败: " + err.Error(),
		})
		return
	}
	defer session.Close()

	// 创建临时文件名（在远程服务器上）
	tempFile := fmt.Sprintf("/tmp/%s_%s", containerID, filepath.Base(request.Path))

	// 将内容写入远程服务器上的临时文件
	// 使用echo命令将内容写入临时文件
	escapedContent := strings.Replace(request.Content, "'", "'\\''", -1) // 转义单引号
	cmd := fmt.Sprintf("echo -n '%s' > %s", escapedContent, tempFile)
	if err := session.Run(cmd); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "创建临时文件失败: " + err.Error(),
		})
		return
	}

	// 创建新会话
	session2, err := sshClient.client.NewSession()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "创建SSH会话失败: " + err.Error(),
		})
		return
	}
	defer session2.Close()

	// 复制文件到容器
	cmd = fmt.Sprintf("docker cp %s %s:%s", tempFile, containerID, request.Path)
	if err := session2.Run(cmd); err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "保存文件失败: " + err.Error(),
		})
		return
	}

	// 创建新会话删除临时文件
	session3, err := sshClient.client.NewSession()
	if err != nil {
		// 仅记录错误，不影响返回结果
		fmt.Printf("删除临时文件创建会话失败: %v\n", err)
	} else {
		defer session3.Close()
		cmd = fmt.Sprintf("rm -f %s", tempFile)
		session3.Run(cmd) // 忽略错误
	}

	c.JSON(http.StatusOK, Response{
		Success: true,
		Message: "文件保存成功",
	})
}

// uploadFile 处理文件上传到容器
func uploadFile(c *gin.Context) {
	containerID := c.Param("id")
	if sshClient == nil {
		c.JSON(http.StatusUnauthorized, Response{
			Success: false,
			Message: "未登录",
		})
		return
	}

	// 获取上传目标路径
	targetPath := c.PostForm("path")
	if targetPath == "" {
		c.JSON(http.StatusBadRequest, Response{
			Success: false,
			Message: "目标路径不能为空",
		})
		return
	}

	// 获取上传的文件
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, Response{
			Success: false,
			Message: "文件上传失败: " + err.Error(),
		})
		return
	}
	defer file.Close()

	// 创建临时文件
	tempDir := os.TempDir()
	tempFilePath := filepath.Join(tempDir, header.Filename)

	tempFile, err := os.Create(tempFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "创建临时文件失败: " + err.Error(),
		})
		return
	}
	defer tempFile.Close()
	defer os.Remove(tempFilePath) // 上传完成后删除临时文件

	// 将上传的文件保存到临时文件
	_, err = io.Copy(tempFile, file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "保存临时文件失败: " + err.Error(),
		})
		return
	}

	// 确保目标目录存在
	session1, err := sshClient.client.NewSession()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "创建SSH会话失败: " + err.Error(),
		})
		return
	}
	defer session1.Close()

	targetDir := filepath.Dir(targetPath)
	session1.Run(fmt.Sprintf("docker exec %s mkdir -p %s", containerID, targetDir))

	// 使用docker cp将临时文件复制到容器
	session, err := sshClient.client.NewSession()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "创建SSH会话失败: " + err.Error(),
		})
		return
	}
	defer session.Close()

	// 将本地临时文件传输到远程主机临时目录
	remoteTempFile := fmt.Sprintf("/tmp/%s_%s", containerID, header.Filename)
	err = sftpUpload(tempFilePath, remoteTempFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "通过SFTP上传文件到远程主机失败: " + err.Error(),
		})
		return
	}

	// 将远程主机的文件复制到容器
	cmd := fmt.Sprintf("docker cp %s %s:%s", remoteTempFile, containerID, targetPath)
	err = session.Run(cmd)

	// 清理远程临时文件
	session2, err := sshClient.client.NewSession()
	if err == nil {
		defer session2.Close()
		session2.Run(fmt.Sprintf("rm -f %s", remoteTempFile))
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "复制文件到容器失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Success: true,
		Message: "文件上传成功",
		Data: map[string]string{
			"filename": header.Filename,
			"size":     fmt.Sprintf("%d", header.Size),
			"path":     targetPath,
		},
	})
}

// downloadFile 从容器下载文件
func downloadFile(c *gin.Context) {
	containerID := c.Param("id")
	filePath := c.Query("path")
	if sshClient == nil {
		c.JSON(http.StatusUnauthorized, Response{
			Success: false,
			Message: "未登录",
		})
		return
	}

	if filePath == "" {
		c.JSON(http.StatusBadRequest, Response{
			Success: false,
			Message: "文件路径不能为空",
		})
		return
	}

	// 创建本地临时目录
	tempDir := os.TempDir()
	tempFilePath := filepath.Join(tempDir, filepath.Base(filePath))

	// 创建远程临时目录
	remoteTempFile := fmt.Sprintf("/tmp/%s_%s", containerID, filepath.Base(filePath))

	// 首先从容器复制文件到远程主机
	session1, err := sshClient.client.NewSession()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "创建SSH会话失败: " + err.Error(),
		})
		return
	}
	defer session1.Close()

	cmd := fmt.Sprintf("docker cp %s:%s %s", containerID, filePath, remoteTempFile)
	err = session1.Run(cmd)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "从容器复制文件失败: " + err.Error(),
		})
		return
	}

	// 清理操作，确保在函数结束时删除临时文件
	defer func() {
		session3, _ := sshClient.client.NewSession()
		if session3 != nil {
			defer session3.Close()
			session3.Run(fmt.Sprintf("rm -f %s", remoteTempFile))
		}
	}()

	// 从远程主机下载文件到本地
	err = sftpDownload(remoteTempFile, tempFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "从远程主机下载文件失败: " + err.Error(),
		})
		return
	}

	// 设置文件下载的HTTP头
	fileName := filepath.Base(filePath)
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	c.Header("Content-Type", "application/octet-stream")
	c.File(tempFilePath)

	// 下载完成后删除本地临时文件
	defer os.Remove(tempFilePath)
}

// sftpUpload 使用SFTP上传文件到远程服务器
func sftpUpload(localFilePath, remoteFilePath string) error {
	// 读取本地文件
	fileData, err := ioutil.ReadFile(localFilePath)
	if err != nil {
		return fmt.Errorf("读取本地文件失败: %v", err)
	}

	// 创建SSH会话
	session, err := sshClient.client.NewSession()
	if err != nil {
		return fmt.Errorf("创建SSH会话失败: %v", err)
	}
	defer session.Close()

	// 写入远程文件
	// 创建目录
	dirCmd := fmt.Sprintf("mkdir -p %s", filepath.Dir(remoteFilePath))
	if err := session.Run(dirCmd); err != nil {
		return fmt.Errorf("创建远程目录失败: %v", err)
	}

	// 创建新的会话用于写入文件
	session2, err := sshClient.client.NewSession()
	if err != nil {
		return fmt.Errorf("创建SSH会话失败: %v", err)
	}
	defer session2.Close()

	// 通过标准输入传输文件
	stdin, err := session2.StdinPipe()
	if err != nil {
		return fmt.Errorf("获取标准输入失败: %v", err)
	}

	// 执行命令，将标准输入定向到文件
	cmd := fmt.Sprintf("cat > %s", remoteFilePath)
	err = session2.Start(cmd)
	if err != nil {
		return fmt.Errorf("启动命令失败: %v", err)
	}

	// 写入文件数据
	_, err = stdin.Write(fileData)
	if err != nil {
		return fmt.Errorf("写入文件数据失败: %v", err)
	}
	stdin.Close()

	// 等待命令完成
	err = session2.Wait()
	if err != nil {
		return fmt.Errorf("等待命令完成失败: %v", err)
	}

	return nil
}

// sftpDownload 使用SFTP从远程服务器下载文件
func sftpDownload(remoteFilePath, localFilePath string) error {
	// 创建SSH会话
	session, err := sshClient.client.NewSession()
	if err != nil {
		return fmt.Errorf("创建SSH会话失败: %v", err)
	}
	defer session.Close()

	// 获取stdout以读取文件内容
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("获取标准输出失败: %v", err)
	}

	// 启动cat命令读取文件
	err = session.Start(fmt.Sprintf("cat %s", remoteFilePath))
	if err != nil {
		return fmt.Errorf("启动命令失败: %v", err)
	}

	// 读取文件内容
	fileData, err := io.ReadAll(stdout)
	if err != nil {
		return fmt.Errorf("读取文件内容失败: %v", err)
	}

	// 等待命令完成
	err = session.Wait()
	if err != nil {
		return fmt.Errorf("等待命令完成失败: %v", err)
	}

	// 写入本地文件
	err = ioutil.WriteFile(localFilePath, fileData, 0644)
	if err != nil {
		return fmt.Errorf("写入本地文件失败: %v", err)
	}

	return nil
}

// handleTerminal 处理WebSocket终端连接
func handleTerminal(c *gin.Context) {
	containerID := c.Param("id")

	// 检查SSH客户端是否已登录
	if sshClient == nil {
		c.JSON(http.StatusUnauthorized, Response{
			Success: false,
			Message: "未登录",
		})
		return
	}

	// 升级HTTP连接至WebSocket
	conn, err := wsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "WebSocket升级失败: " + err.Error(),
		})
		return
	}
	defer conn.Close()

	// 创建SSH会话
	session, err := sshClient.client.NewSession()
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("创建SSH会话失败: "+err.Error()))
		return
	}
	defer session.Close()

	// 设置终端模式
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // 启用回显
		ssh.TTY_OP_ISPEED: 14400, // 输入速度
		ssh.TTY_OP_OSPEED: 14400, // 输出速度
	}

	// 请求伪终端，设置初始大小为80列×24行
	if err := session.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("请求伪终端失败: "+err.Error()))
		return
	}

	// 获取标准输入、输出和错误
	stdin, err := session.StdinPipe()
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("获取标准输入失败: "+err.Error()))
		return
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("获取标准输出失败: "+err.Error()))
		return
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("获取标准错误失败: "+err.Error()))
		return
	}

	// 获取容器名称
	nameSession, err := sshClient.client.NewSession()
	if err == nil {
		defer nameSession.Close()
		cmd := fmt.Sprintf("docker inspect -f '{{.Name}}' %s 2>/dev/null | tr -d '/'", containerID)
		containerName, _ := nameSession.Output(cmd)
		if len(containerName) > 0 {
			// 如果能获取到容器名，使用容器名
			containerID = strings.TrimSpace(string(containerName))
		}
	}

	// 先检测容器中可用的shell
	shellSession, err := sshClient.client.NewSession()
	var cmd string
	if err == nil {
		defer shellSession.Close()
		conn.WriteMessage(websocket.TextMessage, []byte("正在检测容器中可用的shell...\r\n"))

		// 检查bash是否可用
		checkBashCmd := fmt.Sprintf("docker exec %s which bash 2>/dev/null || echo ''", containerID)
		bashPath, _ := shellSession.Output(checkBashCmd)

		if len(strings.TrimSpace(string(bashPath))) > 0 {
			// bash可用
			conn.WriteMessage(websocket.TextMessage, []byte("检测到bash可用，使用bash启动终端\r\n"))
			cmd = fmt.Sprintf("docker exec -it %s bash", containerID)
		} else {
			// 检查sh是否可用
			checkShCmd := fmt.Sprintf("docker exec %s which sh 2>/dev/null || echo ''", containerID)
			shellSession, err = sshClient.client.NewSession()
			if err == nil {
				defer shellSession.Close()
				shPath, _ := shellSession.Output(checkShCmd)

				if len(strings.TrimSpace(string(shPath))) > 0 {
					// sh可用
					conn.WriteMessage(websocket.TextMessage, []byte("bash不可用，检测到sh可用，使用sh启动终端\r\n"))
					cmd = fmt.Sprintf("docker exec -it %s sh", containerID)
				} else {
					// 尝试/bin/sh
					conn.WriteMessage(websocket.TextMessage, []byte("尝试使用/bin/sh...\r\n"))
					cmd = fmt.Sprintf("docker exec -it %s /bin/sh", containerID)
				}
			} else {
				// 会话创建失败，回退到默认行为
				conn.WriteMessage(websocket.TextMessage, []byte("无法创建检测会话，使用bash或sh尝试\r\n"))
				cmd = fmt.Sprintf("docker exec -it %s bash || docker exec -it %s sh || docker exec -it %s /bin/sh", containerID, containerID, containerID)
			}
		}
	} else {
		// 会话创建失败，回退到默认行为
		conn.WriteMessage(websocket.TextMessage, []byte("无法创建检测会话，使用bash或sh尝试\r\n"))
		cmd = fmt.Sprintf("docker exec -it %s bash || docker exec -it %s sh || docker exec -it %s /bin/sh", containerID, containerID, containerID)
	}

	// 启动命令
	conn.WriteMessage(websocket.TextMessage, []byte("正在连接到容器终端...\r\n"))
	err = session.Start(cmd)
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("启动容器终端失败: "+err.Error()+"\r\n正在尝试其他方法...\r\n"))

		// 尝试直接使用容器ID
		session.Close()

		// 创建新会话再次尝试
		session, err = sshClient.client.NewSession()
		if err != nil {
			conn.WriteMessage(websocket.TextMessage, []byte("创建新的SSH会话失败: "+err.Error()+"\r\n"))
			return
		}
		defer session.Close()

		// 重新配置伪终端
		if err := session.RequestPty("xterm-256color", 24, 80, modes); err != nil {
			conn.WriteMessage(websocket.TextMessage, []byte("请求伪终端失败: "+err.Error()+"\r\n"))
			return
		}

		// 获取新的管道
		stdin, _ = session.StdinPipe()
		stdout, _ = session.StdoutPipe()
		stderr, _ = session.StderrPipe()

		// 使用原始容器ID尝试
		cmd = fmt.Sprintf("docker exec -it %s bash || docker exec -it %s sh", c.Param("id"), c.Param("id"))
		err = session.Start(cmd)
		if err != nil {
			conn.WriteMessage(websocket.TextMessage, []byte("第二次尝试启动容器终端失败: "+err.Error()+"\r\n正在尝试最后方法...\r\n"))

			// 最后尝试不使用-t选项
			session.Close()

			// 创建最后一个会话
			session, err = sshClient.client.NewSession()
			if err != nil {
				conn.WriteMessage(websocket.TextMessage, []byte("创建最终SSH会话失败: "+err.Error()+"\r\n"))
				return
			}
			defer session.Close()

			// 重新配置伪终端
			if err := session.RequestPty("xterm-256color", 24, 80, modes); err != nil {
				conn.WriteMessage(websocket.TextMessage, []byte("请求伪终端失败: "+err.Error()+"\r\n"))
				return
			}

			// 获取新的管道
			stdin, _ = session.StdinPipe()
			stdout, _ = session.StdoutPipe()
			stderr, _ = session.StderrPipe()

			// 最后使用-i但不用-t选项
			cmd = fmt.Sprintf("docker exec -i %s bash || docker exec -i %s sh", c.Param("id"), c.Param("id"))
			err = session.Start(cmd)
			if err != nil {
				conn.WriteMessage(websocket.TextMessage, []byte("最终尝试启动容器终端失败: "+err.Error()+"\r\n"))
				return
			}
		}
	}

	// 从终端读取输出并发送到WebSocket
	go func() {
		mReader := io.MultiReader(stdout, stderr)
		buf := make([]byte, 1024)
		for {
			n, err := mReader.Read(buf)
			if err != nil {
				if err != io.EOF {
					conn.WriteMessage(websocket.TextMessage, []byte("读取终端输出错误: "+err.Error()+"\r\n"))
				}
				break
			}

			if n > 0 {
				err = conn.WriteMessage(websocket.BinaryMessage, buf[:n])
				if err != nil {
					break
				}
			}
		}
	}()

	// 从WebSocket读取输入并发送到终端
	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			// WebSocket连接关闭或出错，发送终止信号
			fmt.Println("WebSocket连接关闭:", err)

			// 尝试发送终止信号
			stdin.Write([]byte{3, 4}) // Ctrl+C, Ctrl+D
			stdin.Write([]byte("exit\n"))

			// 等待一段时间后退出循环
			time.Sleep(100 * time.Millisecond)
			break
		}

		if messageType == websocket.TextMessage || messageType == websocket.BinaryMessage {
			// 检查是否是调整窗口大小的消息
			if len(p) > 2 && p[0] == 'r' && p[1] == 's' {
				// 消息格式: "rs:行数:列数"
				parts := strings.Split(string(p), ":")
				if len(parts) == 3 {
					// 忽略错误处理以简化代码
					rows := 24 // 默认值
					cols := 80 // 默认值
					fmt.Sscanf(parts[1], "%d", &rows)
					fmt.Sscanf(parts[2], "%d", &cols)
					session.WindowChange(rows, cols)
					continue
				}
			}

			_, err := stdin.Write(p)
			if err != nil {
				break
			}
		}
	}

	// 等待命令结束
	// 使用通道和超时机制来防止阻塞
	done := make(chan struct{})
	go func() {
		session.Wait()
		close(done)
	}()

	// 等待进程结束，最多等待1秒
	select {
	case <-done:
		// 进程已正常结束
	case <-time.After(1 * time.Second):
		// 超时，强制关闭会话
		fmt.Println("终端会话超时，强制关闭")
	}
}

// handleHostTerminal 处理宿主机终端连接
func handleHostTerminal(c *gin.Context) {
	// 检查SSH客户端是否已登录
	if sshClient == nil {
		c.JSON(http.StatusUnauthorized, Response{
			Success: false,
			Message: "未登录",
		})
		return
	}

	// 升级HTTP连接至WebSocket
	conn, err := wsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "WebSocket升级失败: " + err.Error(),
		})
		return
	}
	defer conn.Close()

	// 创建SSH会话
	session, err := sshClient.client.NewSession()
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("创建SSH会话失败: "+err.Error()))
		return
	}
	defer session.Close()

	// 设置终端模式
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // 启用回显
		ssh.TTY_OP_ISPEED: 14400, // 输入速度
		ssh.TTY_OP_OSPEED: 14400, // 输出速度
	}

	// 请求伪终端，设置初始大小为80列×24行
	if err := session.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("请求伪终端失败: "+err.Error()))
		return
	}

	// 获取标准输入、输出和错误
	stdin, err := session.StdinPipe()
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("获取标准输入失败: "+err.Error()))
		return
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("获取标准输出失败: "+err.Error()))
		return
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("获取标准错误失败: "+err.Error()))
		return
	}

	// 开始会话
	err = session.Shell()
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("启动Shell失败: "+err.Error()+"\r\n"))
		return
	}

	// 从终端读取输出并发送到WebSocket
	go func() {
		mReader := io.MultiReader(stdout, stderr)
		buf := make([]byte, 1024)
		for {
			n, err := mReader.Read(buf)
			if err != nil {
				if err != io.EOF {
					conn.WriteMessage(websocket.TextMessage, []byte("读取终端输出错误: "+err.Error()+"\r\n"))
				}
				break
			}

			if n > 0 {
				err = conn.WriteMessage(websocket.BinaryMessage, buf[:n])
				if err != nil {
					break
				}
			}
		}
	}()

	// 从WebSocket读取输入并发送到终端
	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			// WebSocket连接关闭或出错，发送终止信号
			fmt.Println("WebSocket连接关闭:", err)

			// 尝试发送终止信号
			stdin.Write([]byte{3, 4}) // Ctrl+C, Ctrl+D
			stdin.Write([]byte("exit\n"))

			// 等待一段时间后退出循环
			time.Sleep(100 * time.Millisecond)
			break
		}

		if messageType == websocket.TextMessage || messageType == websocket.BinaryMessage {
			// 检查是否是调整窗口大小的消息
			if len(p) > 2 && p[0] == 'r' && p[1] == 's' {
				// 消息格式: "rs:行数:列数"
				parts := strings.Split(string(p), ":")
				if len(parts) == 3 {
					// 忽略错误处理以简化代码
					rows := 24 // 默认值
					cols := 80 // 默认值
					fmt.Sscanf(parts[1], "%d", &rows)
					fmt.Sscanf(parts[2], "%d", &cols)
					session.WindowChange(rows, cols)
					continue
				}
			}

			_, err := stdin.Write(p)
			if err != nil {
				break
			}
		}
	}

	// 等待命令结束
	// 使用通道和超时机制来防止阻塞
	done := make(chan struct{})
	go func() {
		session.Wait()
		close(done)
	}()

	// 等待进程结束，最多等待1秒
	select {
	case <-done:
		// 进程已正常结束
	case <-time.After(1 * time.Second):
		// 超时，强制关闭会话
		fmt.Println("宿主机终端会话超时，强制关闭")
	}
}
