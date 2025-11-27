# 2FA TOTP Generator

一个简单的命令行双因素认证 (2FA) TOTP 生成器，使用 C 语言编写。

## 作者信息

- **Author**: zhlhlf
- **Email**: zhlhlf@gmail.com

## 功能特点

- 支持标准的 TOTP 算法 (HMAC-SHA1)
- 命令行界面，操作简单
- 支持添加账户 (支持批量导入)
- 支持删除账户
- 支持查看所有账户或指定账户的验证码
- 验证码绿色高亮显示
- 显示当前验证码剩余有效时间

## 编译方法

使用 GCC 编译：

```bash
gcc 2fa.c -o 2fa
```

## 使用说明

### 1. 查看所有验证码

直接运行程序即可显示所有已保存账户的验证码及剩余时间。

```bash
./2fa
```

输出示例：

```
1. git.zhlhlf.com:zhouhoulin: 123456 (25s)
2. google:test: 654321 (25s)
```

### 2. 添加账户

使用 `a` 参数添加账户。支持批量导入，每行输入一个 `otpauth` URL，输入空行结束。

```bash
./2fa a
```

输入示例：

```
otpauth://totp/zm.com%3Azhouhoulin?secret=HGLxxxx42A3&algorithm=SHA1&digits=6&period=30&issuer=git
```

### 3. 删除账户

使用 `d` 参数删除账户。程序会列出所有账户，输入序号即可删除。

```bash
./2fa d
```

### 4. 查看指定账户

输入账户序号查看特定账户的验证码。

```bash
./2fa 1
```

输出示例：

```
123456 (25s)
```

## 数据存储

账户数据保存在用户主目录下的 `.2fa` 文件中。

- Windows: `%USERPROFILE%\.2fa`
- Linux/macOS: `~/.2fa`

## 依赖

- 标准 C 库
