<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>SSRF 靶场 - Hello-CTF</title>
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #34495e;
            --background-color: #ffffff;
            --text-color: #2c3e50;
            --code-background: #f4f4f4;}

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;font-family: 'Arial', 'Microsoft YaHei', sans-serif;
        }

        body {
            background-color: var(--background-color);
            color: var(--text-color);
            line-height: 1.6;
        }

        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
        }

        .challenge-title {
            text-align: center;
            color: var(--primary-color);
            margin-bottom: 2rem;
        }

        .challenge-description {
            background-color: var(--code-background);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            margin-top: 1rem;
        }

        .challenge-input {
            width: 100%;
            padding: 0.8rem;
            margin-bottom: 1rem;
            border: 1px solid var(--secondary-color);
            border-radius: 4px;}

        .submit-btn {
            display: block;
            width: 100%;
            padding: 0.8rem;
            background-color: var(--primary-color);
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.3s;
        }

        .submit-btn:hover {
            background-color: var(--secondary-color);
        }

        .source-code {
            background-color: var(--code-background);
            border-radius: 8px;
            padding: 1rem;
            font-family: 'Consolas', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            margin-top: 1rem;
        }

        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .footer {
            text-align: center;
            padding: 1rem 0;
            margin-top: 2rem;
            border-top: 1px solid var(--secondary-color);
            color: var(--text-color);
            font-size: 0.9rem;
        }
        
        .footer a {
            color: var(--primary-color);
            text-decoration: none;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="challenge-title">Hello SSRF | Hello-CTF系列靶场</h1>
        <div class="challenge-description">
            <h2>Level 8 | evalFastcgi </h2>
            <p>已启用php-fpm，仅监听127.0.0.1:9000，查看下面的phpinfo获取更多信息w</p>
        </div>

        <form id="ssrfForm">
            <input type="url" id="urlInput" class="challenge-input"placeholder="输入要请求的 URL（例如：http://example.com）" 
                   required>
            <button type="submit" class="submit-btn">发送请求</button>
        </form>

        <div id="result" class="challenge-description" style="display:none;">
            <h3>请求结果</h3>
            <pre id="resultContent"></pre>
        </div>

        <div class="source-code">
            <h3>后端源代码</h3>
            <code>
            <?php
                highlight_file('ssrf.php');
            ?>
            </code>
        </div>
        <div class="challenge-description">
            <h3>PHP信息</h3>
            <div class="phpinfo-container">
                <?php
                    // 创建一个缓冲区捕获phpinfo输出
                    ob_start();
                    phpinfo();
                    $phpinfo = ob_get_contents();
                    ob_end_clean();
                    
                    // 提取body内容
                    preg_match('/<body[^>]*>(.*?)<\/body>/si', $phpinfo, $matches);
                    if (isset($matches[1])) {
                        // 提取原始phpinfo中的表格样式
                        preg_match('/<style(.*?)<\/style>/si', $phpinfo, $style_matches);
                        if(isset($style_matches[0])) {
                            // 只保留表格相关的CSS
                            $filtered_style = preg_replace('/body\s*{.*?}|a\s*{.*?}|h1\s*{.*?}|h2\s*{.*?}/si', '', $style_matches[0]);
                            echo $filtered_style;
                        }
                        
                        echo '<div style="overflow-x:auto;">';
                        // 输出内容，但保留表格结构
                        echo $matches[1];
                        echo '</div>';
                    }
                ?>
            </div>
        </div>
    </div>

    <script>
        document.getElementById('ssrfForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const url = document.getElementById('urlInput').value;
            fetch('ssrf.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `url=${encodeURIComponent(url)}`
            })
            .then(response => response.text())
            .then(data => {
                const resultDiv = document.getElementById('result');
                const resultContent = document.getElementById('resultContent');
                resultContent.textContent = data;
                resultDiv.style.display = 'block';
            })
            .catch(error => {
                console.error('Error:', error);
            });
        });
    </script>
<footer class="footer">
        <p>© 2025 <a href="https://hello-ctf.com" target="_blank">Hello-CTF</a>. All rights reserved.</p>
    </footer>
</body>
</html>