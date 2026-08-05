# GitHub 权限需求与 Token 导出指南

> 面向项目作者（lipeiying032）。要把本仓库开源推送到 GitHub，需要你提供一个
> **GitHub Personal Access Token（PAT）**，并配置 **git 用户名/邮箱**。本文档说明
> 需要什么权限、怎么在 GitHub 网页上导出、以及怎么把 token 安全地交给 Hermes。

---

## 1. 需要提供什么

| 项目 | 是否必需 | 说明 |
|---|---|---|
| GitHub Personal Access Token（PAT） | ✅ 必需 | 用于 `git push` 上传仓库（以及后续创建 Release 发布探针预编译二进制） |
| git 用户名（user.name） | ✅ 必需 | 提交记录的作者名，建议填 `lipeiying032` |
| git 邮箱（user.email） | ✅ 必需 | 提交记录的作者邮箱，建议用 GitHub 的 noreply 邮箱（见 3.2 节） |

不需要提供：SSH 私钥、账号密码、仓库内容（仓库文件已在本机整理好）。

---

## 2. Token 需要的精确权限

推荐使用 **Fine-grained token（细粒度 token）**，只授权本项目仓库，比 classic token 更安全：

| 权限项 | 设置值 | 作用 |
|---|---|---|
| Repository access | **Only select repositories** → 勾选 `h3-reality-deploy` | 只允许操作这一个仓库 |
| Contents | **Read and write** | 推送代码、创建 Release 所需 |
| Metadata | **Read-only**（必选，GitHub 自动勾选） | 读取仓库元数据 |

> 如果选择 classic token：勾选 **`repo`**（完整仓库读写）即可，`repo` 自带 Metadata 读取。
> classic token 无法限定单个仓库，授权范围是整个账号，用完请立刻 revoke（见第 4 节）。

---

## 3. 逐步导出方法（英文界面 + 中文说明）

### 3.1 生成 Token

以下路径基于 GitHub 英文界面。推荐路径 **A（Fine-grained）**；路径 B（classic）作为备选。

#### 路径 A：Fine-grained token（推荐）

1. 打开 `https://github.com`，登录账号 → 点击**右上角头像**（profile photo）→ 点击
   **Settings**（设置）。
2. 在左侧设置菜单**滚动到最底部**，点击 **Developer settings**（开发者设置）。
3. 左侧点击 **Personal access tokens**（展开）→ 点击 **Fine-grained tokens**。
4. 点击右上角 **Generate new token**（生成新 token）。
5. 按提示填写：
   - **Token name**：随便起一个，例如 `h3-reality-deploy-push`；
   - **Expiration**（有效期）：建议选 `30 days` 或自定义短期，用完后随时可 revoke；
   - **Repository access**：选择 **Only select repositories**，然后在右侧仓库列表勾选
     `h3-reality-deploy`（如果仓库还没建，先看 3.3 节建好再回来勾选）；
   - **Permissions → Repository permissions**：把 **Contents** 设为
     **Read and write**（Metadata 会自动变成 Read-only，保持即可）。
6. 点击页面底部 **Generate token**。
7. 页面会显示一串以 `github_pat_` 开头的 token（如 `github_pat_xxxxxx`）——
   **只显示这一次**，立即点击复制按钮复制，妥善保存。

#### 路径 B：Tokens (classic)

1. 打开 `https://github.com` → 右上角头像 → **Settings**。
2. 左侧最底部 → **Developer settings**。
3. 左侧 **Personal access tokens** → **Tokens (classic)**。
4. 点击 **Generate new token** → **Generate new token (classic)**。
5. 勾选权限 **`repo`**（完整控制私有仓库，含推送与 Release）。
6. 点击 **Generate token**，复制以 `ghp_` 开头的 token——同样**只显示一次**。

### 3.2 配置 git 用户名与邮箱（本机执行）

```bash
# 全局配置（推荐，配置一次即可）
git config --global user.name "lipeiying032"
git config --global user.email "你的邮箱@example.com"

# 查看是否生效
git config --global user.name
git config --global user.email
```

邮箱建议用 GitHub 提供的隐私邮箱：`你的用户ID+lipeiying032@users.noreply.github.com`
（GitHub → Settings → Emails 页面可以查到，勾选 "Keep my email addresses private"
后就是这种格式）。

### 3.3 创建远程空仓库（可选，若尚未创建）

GitHub 不会在 `git push` 时自动建仓库。请先在网页上创建：

1. 右上角 `+` → **New repository**；
2. Repository name 填 `h3-reality-deploy`，设为 **Private**（正式公开可后改）；
3. **不要**勾选 "Add a README file" / ".gitignore" / "license"（本仓库已自带）；
4. 点击 **Create repository**。

---

## 4. 安全提示

- Token 相当于仓库的钥匙：**只给 Hermes 用**，不要截图、不要发到聊天/邮件/公开渠道；
- 本机仓库已通过 `.gitignore` 排除敏感文件，但 token 请**不要**写进任何仓库文件；
- 用完（push + 建 Release 完成）后可以在 GitHub → Settings → Developer settings →
  Personal access tokens 里 **Revoke**，随时作废；
- 若怀疑 token 泄露，立即 revoke 并重新生成一个。

---

## 5. 拿到 Token 后怎么交给 Hermes

两种方式任选（推荐方式 A）：

### 方式 A：写入 Hermes 环境文件（推荐）

把 token 写入 `/root/.hermes/.env`：

```bash
echo 'GITHUB_TOKEN=github_pat_xxxxxx' >> /root/.hermes/.env
```

之后直接对 Hermes 说“token 已写入，开始 push”，Hermes 会用该 token 完成
`git push` 与后续 Release 创建。

### 方式 B：push 时作为凭据手动输入

对 Hermes 说“用我提供的 token push”，然后在 push 时按提示粘贴：

```bash
git push https://github.com/lipeiying032/h3-reality-deploy.git main
# 用户名填 lipeiying032，密码（Password）粘贴 token
```

也可以临时写在 URL 里（注意会留在 shell 历史，用完建议 `history -c`）：

```bash
git push https://lipeiying032:github_pat_xxxxxx@github.com/lipeiying032/h3-reality-deploy.git main
```

> 首次提交时本机若未配置 git 用户名/邮箱，Hermes 不会自动替你设置（避免写错身份），
> 请先按 3.2 节配置，再 push。

---

## 6. Push 之后（供参考，不需要现在做）

1. `git push -u origin main` 推送代码；
2. 创建 GitHub Release（`v1.0.0`），上传预编译探针
   `probe-h3-sni-linux-amd64`——这样脚本内置的 Release 下载地址
   （`https://github.com/lipeiying032/h3-reality-deploy/releases/latest/download/probe-h3-sni-linux-amd64`）
   才会生效；
3. 确认无误后，在仓库 Settings → General → Danger Zone 把仓库改为 **Public**。
