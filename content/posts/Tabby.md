---
share: "true"
date: 2024-02-18
---

 
![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhCav4O5xymQj4Xib08nB1Y3qZaaaDUv3MupIXUrLfU9bmtDQdJB33qoQ/640?wx_fmt=png&from=appmsg)

GitHub 上已经有 52.8k 的 star 了，这说明 Tabby 非常的受欢迎：

> https://github.com/eugeny/tabby


Tabby 是一个高度可定制化的 跨平台的终端工具，支持 Windows、macOS 和 Linux，自带 SFTP 功能，能与 Linux 服务器轻松传输文件，支持多种主题，界面炫酷，插件丰富。

## 一、安装 Tabby

直接到官网 tabby.sh 点击「download」按钮就可以跳转到下载页面，最新的 release 版本是 1.0.205。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWh7bFu2JXroyOMvDzh4LtXF207y4R1HibC3S8xYz5icicFwAJU2ZZKCyyQQ/640?wx_fmt=png&from=appmsg)

Linux 和 Windows 的比较好选，macOS 分为两个版本，一个是 arm64，一个是 x86-64，什么意思呢？

这里简单普及下哈。

> ARM是英国ARM公司提供一种CPU架构的知识产权，目前主流的手机和平板电脑都采用ARM架构，但 ARM 不生产芯片，只是从各种嵌入式设备、智能手机、平板电脑、智能穿戴和物联网设备体内的上亿颗处理器中“抽成”。

Apple M1 是苹果公司的第一款基于ARM架构的自研处理器单片系统。

> X86_X64 源于英特尔几十年前出品的CPU型号8086，包括后续型号8088/80286/80386/80486/80586等等，8086以及8088被当时的IBM采用，制造出了名噪一时的IBM PC机，从此个人电脑风靡一时。

详情可参阅下面这篇：

> https://www.cnblogs.com/zhaoqingqing/p/13145115.html

从这一点上可以证明，Tabby 的更新是非常勤快的，连 macOS 的最新芯片 M1 都支持了，厉害了呀，我的虎斑猫（Tabby）！

按照提示，一步步安装就 OK 了。完成后打开，这界面还是非常炫酷的。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWh78Wy9k4moL84u14WdCGGZMsNV3Hpcb5YueafSy7UnnJLJhFqbAantQ/640?wx_fmt=png&from=appmsg)

## 二、SSH 连接

SSH，也就是 Secure Shell（安全外壳协议），是一种加密的网络传输协议，可在不安全的网络中为网络服务提供安全的传输环境，通过在网络中创建安全隧道来实现 SSH 客户端和服务器端之间的连接。

那不妨我们就使用 Tabby 来与服务器建立一个 SSH 连接吧。

点击「setting」→「profiles & connections」→「new profile」。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWh8PC5kBD6lOqIIpzjsbKf5mUbROOtMaHK9gxiaIy1rud4GtaY9mmXiaZA/640?wx_fmt=png&from=appmsg)

填写服务器的 IP 地址和密码，然后点击「save」。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhVkSAGavOkyXjcpKJrgW3PTHUYI20rRDzBuwBRFC83Dk3A5QaqDDIWw/640?wx_fmt=png&from=appmsg)

之后点击「运行」按钮，就可以进入到终端页面了。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhl6iahk9JdcyY9fFANS2TqRPNUt2icfvCjLWsIiasaPZJDYPebfwXRXUBA/640?wx_fmt=png&from=appmsg)

好了，现在可以对服务器进行操作了，执行下 top 命令可以查看服务器上正在运行的进程信息。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhoTe7c6AyEDOZuI4k5Xhb8QGSWSARGGKBiabMqyTpLnUvh50F4rsrmuQ/640?wx_fmt=png&from=appmsg)

## 三、SFTP 传输文件

Tabby 集成了 SFTP，所以上传下载文件就变得非常的简单。只需要点击一下「SFTP」图标就可以打开文件传输窗口。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhZ5lmv5C0SVXodK9AY9zKtSkV7nR6bqmCyCic3BB0FIm9qnI361jSo4Q/640?wx_fmt=png&from=appmsg)

上传的时候支持拖拽，完成后会弹出文件传输成功的提示消息。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhviaiccZibaUyYEgCOGYK2KXvJLPGWAYa4e7OmaOpiaeo3Uw1lbef0IhfAQ/640?wx_fmt=png&from=appmsg)

下载的时候点击要下载的文件，然后会弹出存储对话框，选择对应的文件夹，以及修改对应的文件名点击「存储」就可以了。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhlz5UPnEnwBWFSvBvlfQ1IDjX5oHCgGWI8pBNev5FUHUNj8GqRhsYJg/640?wx_fmt=png&from=appmsg)

## 四、配置 Tabby

「Settings」 的面板下有一个「Appearance」的菜单，可以对 Tabby 的外观进行设置，比如说调整字体，比如说自定义样式。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhsJSwAAU038ynDEJJJB4lcRSYXutpBwQK2frZVmsBZ0nOjQfu0QcYibQ/640?wx_fmt=png&from=appmsg)

「Appearance」的菜单可以对 Tabby 的配色方案进行修改，里面的主题非常多，不过我感觉默认的就挺不错，毕竟是官方推荐的。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhrZMD58gr5GpX84mPiaz0GI6tJ3bVQS90qol0ggdY4vqA9WaCxBCYBicQ/640?wx_fmt=png&from=appmsg)

「Plugins」 菜单中还有不少插件可供扩展。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhWSjymzDewnUFgm1hryL4ycJL9Ws3MSGdOv2tlDUcwkk4pyib1YIe8cA/640?wx_fmt=png&from=appmsg)

- clickable-links - 使终端中的路径和 URL 可点击
    
- docker - 连接到 Docker 容器
    
- title-control - 允许通过提供要删除的前缀、后缀和/或字符串来修改终端选项卡的标题
    
- quick-cmds - 快速向一个或所有终端选项卡发送命令
    
- save-output - 将终端输出记录到文件中
    

这里重点说一下「sync config」 这个插件，可以将配置同步到Github或者Gitee的插件。点击「Get」就可以安装，之后会提示你重启生效。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhEeQw5sQhjsx4DJ3Foeyr49gv6TtMMlrdX3WxTQKgj7JtzNOLWOPAew/640?wx_fmt=png&from=appmsg)

生效后点击「Sync Config」菜单，就可以看到配置项了，类型可以选择 GitHub、Gitee、GitLab。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhTfNpcPusOqtKmHy4iccaTTzOxw7HMYb0oKeTibFfVCHic5kBqGo0xuLZA/640?wx_fmt=png&from=appmsg)

这里以 Gitee 为例，进入个人 Gitee 主页，左侧菜单中选择「私人令牌」，然后点击「生成新令牌」。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhSr6icsia55HbswicWicSuSsofe3LUs8WqKZHYSZJEZkCwia0435uia27uarg/640?wx_fmt=png&from=appmsg)

提交后会生成 token，复制到 Tabby 的 Token 输入框中，然后点击「Upload config」，就可以看到配置信息同步成功了。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhKm2mB4ekoIujxN4KcMiakwdvy6BNZgmKSfy35icTy8NXlEE8c8iaIOIdw/640?wx_fmt=png&from=appmsg)

「Window」 菜单中可以对当前窗口进行设置，比如说改变窗口的主题为 Paper，改变 tab 的位置到底部等等。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhBQ9zGVscI9YToBZpgloS4whZ8nPC9Qx8K43FLd5PhSrXg3licVvu72w/640?wx_fmt=png&from=appmsg)

## 五、总结

SSH 连接和 SFTP 传输恐怕是我们操作 Linux 服务器最常用的两个功能了，那 Tabby 对这两个功能的支持非常的友好，足够的轻量级。关键它是跨平台的，Windows、macOS 都可以用，再把配置信息同步到云上后，多平台下切换起来简直不要太舒服。

Windows 用户习惯用 Xshell，macOS 用户习惯用 iTerm2，但这两款工具都没办法跨平台，多平台操作的用户就可以选择 Tabby 来体验一下，真心不错。

![](https://mmbiz.qpic.cn/mmbiz_png/z40lCFUAHpk6M4EKJ4j5AtPzWUv2MVWhIFDSicLmDuIjicr5vKay4xZnj4HWibAfKPzZFNPWa5ttgib7SO71FXhqkA/640?wx_fmt=png&from=appmsg)