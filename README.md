# NetBlockTweak

基于 [Theos](https://theos.dev) 的 iOS 越狱 Tweak,用于注入指定的**测试 App**,按可配置规则对
App 内的 **HTTP / HTTPS / TCP / UDP** 流量进行拦截或放行,方便做弱网、接口不可用、被墙、
异常网络等场景的自动化/手动测试。

> ⚠️ 仅限在你拥有合法权限的测试设备与测试 App 上使用,不要用于未经授权的第三方 App。

## 原理

采用三层拦截,保证覆盖面:

1. **低层 socket 层**(`Tweak.xm` 中 `%hookf`)
   - Hook `connect`:拦截所有走 `connect()` 建连的 TCP,以及已连接的 UDP socket。
   - Hook `sendto`:拦截未 connect、直接 `sendto` 发包的 UDP。
   - Hook `getaddrinfo`:记录域名解析出的 IP,供规则按域名匹配时,在只拿得到 IP 的
     socket 层也能命中。
2. **CFNetwork 层**
   - Hook `CFStreamCreatePairWithSocketToHost` / `CFStreamCreatePairWithSocketToCFHost`:
     部分老代码/三方库直接用 CFStream 建流,这里能拿到原始域名,在建流阶段就直接判断
     拦截,不依赖 IP 反查。
   - Hook `CFHostStartInfoResolution`:CFNetwork 有时用 `CFHost` 而不是 `getaddrinfo`
     做域名解析,这里同样把解析出的 IP 缓存起来,补全 socket 层的域名匹配。
3. **高层 NSURLProtocol 层**
   - 自定义 `NBURLProtocol`,拦截 `NSURLSession` / `NSURLConnection` 及绝大多数基于它们
     封装的三方网络库(AFNetworking / Alamofire 等)发出的 HTTP/HTTPS 请求。
   - 同时 hook 了 `NSURLSessionConfiguration -protocolClasses`,覆盖 App 显式指定
     protocolClasses、导致全局 `registerClass:` 不生效的情况。

两层各自独立按规则判断,即使某个 App 绕过了其中一层(比如自己撸的 socket 不走
NSURLSession),另一层通常仍能生效。

## 规则文件

运行时从设备上的 JSON 文件读取规则,**每 3 秒轮询热加载**,改规则不需要重新打包/重启 App:

- rootless 越狱: `/var/jb/var/mobile/Library/Preferences/com.yourteam.netblocktweak.rules.json`
- rootful 越狱: `/var/mobile/Library/Preferences/com.yourteam.netblocktweak.rules.json`

`rules.example.json` 里已经加了三条示例,用来演示按域名拦截三方 SDK 的场景
(`ios.perfsight.qq.com` 是腾讯性能监控 SDK 上报地址,`ir-sdk.dun.163.com` 是网易易盾风控 SDK
地址,`www.163.com` 是普通站点),方便你验证:拦截后 App 里对应的统计上报/风控校验/页面请求
是否按预期失败、App 是否有合理的降级逻辑,而不是崩溃或卡死:

```json
{
  "log": true,
  "default_action": "allow",
  "rules": [
    { "host": "www.163.com",          "port": 0, "proto": "any", "action": "block" },
    { "host": "ios.perfsight.qq.com", "port": 0, "proto": "any", "action": "block" },
    { "host": "ir-sdk.dun.163.com",   "port": 0, "proto": "any", "action": "block" }
  ]
}
```

字段说明:

| 字段 | 说明 |
|---|---|
| `log` | 是否记录日志到 `/var/mobile/Library/Logs/NetBlockTweak.log` 及系统日志 |
| `default_action` | 没有任何规则命中时的默认动作,`allow` 或 `block` |
| `rules[].host` | 精确域名 / `*.example.com` 通配后缀 / IP / `*` 匹配所有 |
| `rules[].port` | 目标端口,`0` 表示任意端口 |
| `rules[].proto` | `tcp` / `udp` / `any` |
| `rules[].action` | `block` 拦截 或 `allow` 放行 |

规则按数组顺序匹配,**命中第一条即生效**,可以把更精确的规则放前面、通配规则放后面。

## 构建

1. 安装 [Theos](https://theos.dev/docs/installation) 及对应的 iOS SDK。
2. 修改以下几处占位信息:
   - `NetBlockTweak.plist`:把 `com.example.targetapp` 换成你要测试的目标 App 的 Bundle ID。
   - `Makefile`:把 `INSTALL_TARGET_PROCESSES` 换成目标 App 的可执行文件名
     (在 App 的 `Info.plist` 的 `CFBundleExecutable` 里能找到)。
   - `control`:按需改 `Package` / `Maintainer` 等信息。
3. 编译打包:

```bash
export THEOS=/opt/theos   # 按你本机实际路径
make package FINALPACKAGE=1
```

4. 安装到已越狱的测试设备(需要设备可 SSH,或用 `make install`):

```bash
export THEOS_DEVICE_IP=你的设备IP
make package install FINALPACKAGE=1
```

或者把生成的 `.deb` 拷贝到设备后用 Sileo/Zebra 等包管理器安装。

5. 把 `rules.example.json` 拷贝到设备上对应路径(改名成
   `com.yourteam.netblocktweak.rules.json`),然后按需编辑规则,启动/重启目标 App 即可生效。

## 局限性

- 需要越狱设备(rootful 或 rootless 均可,rootless 下依赖 ElleKit/libhooker 兼容
  MobileSubstrate API)。
- 高层 NSURLProtocol 方案对走系统 `URLSession`/`NSURLConnection` 的请求覆盖较好;
  如果目标 App 使用了自己实现的、完全绕开 BSD socket 高层封装的私有协议栈(极少见),
  可能需要针对性再加 hook 点,可以在 `Tweak.xm` 里参考现有写法扩展。
- 不做流量篡改/中间人解密,只做"放行/拦截"的开关判断,定位是**测试用的开关式防火墙**,
  不是抓包/改包工具。如果需要抓包分析明文内容,配合 Charles / mitmproxy 等代理工具使用更合适。

## 目录结构

```
NetBlockTweak/
├── control                  # Theos 包信息
├── Makefile                 # 构建脚本
├── NetBlockTweak.plist      # 注入目标过滤(Bundle ID / 可执行文件名)
├── Tweak.xm                 # 核心实现:规则引擎 + socket 层 hook + NSURLProtocol 层 hook
├── rules.example.json       # 规则文件示例
└── README.md
```

## 推送到 GitHub

本地已经初始化好 git 仓库,你只需要在 GitHub 建好空仓库后:

```bash
cd NetBlockTweak
git remote add origin git@github.com:<你的用户名>/NetBlockTweak.git
git branch -M main
git push -u origin main
```

## License

MIT
