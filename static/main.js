// 配置require.js
require.config({
    paths: {
        'vs': 'https://cdn.bootcdn.net/ajax/libs/monaco-editor/0.36.1/min/vs'
    }
});

// 等待页面加载完成
window.onload = function() {
    // 初始化Monaco Editor
    require(['vs/editor/editor.main'], function() {
        window.editor = monaco.editor.create(document.getElementById('editor'), {
            value: '',
            language: 'plaintext',
            theme: 'vs-dark',
            automaticLayout: true,
            minimap: {
                enabled: true
            },
            scrollBeyondLastLine: false,
            fontSize: 14,
            lineNumbers: 'on',
            renderWhitespace: 'selection',
            tabSize: 4,
            wordWrap: 'on'
        });

        // 初始化Vue实例
        new Vue({
            el: '#app',
            data: {
                containerId: '',
                fileTree: [],
                currentFile: null,
                defaultProps: {
                    children: 'children',
                    label: 'label'
                }
            },
            methods: {
                loadContainerFiles() {
                    if (!this.containerId) {
                        this.$message.warning('请输入容器ID');
                        return;
                    }
                    
                    fetch(`/api/container/${this.containerId}/files`)
                        .then(response => response.json())
                        .then(data => {
                            this.fileTree = this.formatFileTree(data);
                            this.$message.success('文件加载成功');
                        })
                        .catch(error => {
                            this.$message.error('加载文件失败：' + error.message);
                        });
                },
                formatFileTree(files) {
                    return files.map(file => ({
                        label: file.name,
                        children: file.children ? this.formatFileTree(file.children) : null,
                        path: file.path
                    }));
                },
                handleNodeClick(data) {
                    if (!data.children) {
                        this.currentFile = data.path;
                        this.loadFile(data.path);
                    }
                },
                loadFile(path) {
                    fetch(`/api/container/${this.containerId}/file?path=${encodeURIComponent(path)}`)
                        .then(response => response.text())
                        .then(content => {
                            const language = this.getLanguageFromPath(path);
                            monaco.editor.setModelLanguage(window.editor.getModel(), language);
                            window.editor.setValue(content);
                        })
                        .catch(error => {
                            this.$message.error('加载文件失败：' + error.message);
                        });
                },
                getLanguageFromPath(path) {
                    const ext = path.split('.').pop().toLowerCase();
                    const languageMap = {
                        'js': 'javascript',
                        'json': 'json',
                        'py': 'python',
                        'java': 'java',
                        'cpp': 'cpp',
                        'c': 'c',
                        'go': 'go',
                        'rs': 'rust',
                        'html': 'html',
                        'css': 'css',
                        'md': 'markdown',
                        'yml': 'yaml',
                        'yaml': 'yaml',
                        'xml': 'xml',
                        'sh': 'shell',
                        'bash': 'shell',
                        'sql': 'sql'
                    };
                    return languageMap[ext] || 'plaintext';
                },
                saveFile() {
                    if (!this.currentFile) {
                        this.$message.warning('请先选择一个文件');
                        return;
                    }

                    const content = window.editor.getValue();
                    fetch(`/api/container/${this.containerId}/file?path=${encodeURIComponent(this.currentFile)}`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'text/plain'
                        },
                        body: content
                    })
                    .then(response => {
                        if (response.ok) {
                            this.$message.success('文件保存成功');
                        } else {
                            throw new Error('保存失败');
                        }
                    })
                    .catch(error => {
                        this.$message.error('保存文件失败：' + error.message);
                    });
                }
            }
        });
    });
}; 