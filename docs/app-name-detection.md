# 小程序名称识别（AppName）机制分析与失效原因

> 分析对象：`wux1an/wxapkg` PR #62（commit `65f791073284e9023d851d4f091c3ef02fb02926`）引入的名称识别逻辑。
> 结论基于对本机真实微信数据目录的实测复现，**不是推测**。
>
> **状态：已修复。** 第 8 节记录了修复内容与验证结果。

---

## 1. 结论速览

PR #62 新增的「识别名称」功能在本机**对所有小程序 100% 失效**，根因有两个，且都在逻辑本身，与打包无关：

| # | 根因 | 影响 |
|---|------|------|
| 1 | `app-config.json` 在真实微信 v4 包中**不包含任何名称字段**，且 `global.window` 里**没有 `navigationBarTitleText`** | `package-config` / `navigation-title` 两个来源全部落空 |
| 2 | 代码候选（`code-candidate`）的 4 个正则**在真实 `app-service.js` 中全部零匹配**，同时候选文件白名单**漏了 `__PLUGINCODE__.wxapkg`** | `code-candidate` 来源落空 |
| 3 | 本地元数据的 `knownLocalMetadataFiles` 白名单里，真实文件是 `initial-rendering-cache-config.json`，内容仅 `{}`（2 字节）；且微信 v4 的真实元数据在 **MMKV 二进制**里（加密） | `local-metadata` 来源落空 |

因此最终返回空结果，UI 显示「未识别名称」。

实测结果（本机微信 v4）：

```
wx38ae5595accae89e main=__APP__.wxapkg      hasConfig=true  -> name="" src=""
wx3d52dd4807d5e0fa main=__APP__.wxapkg      hasConfig=true  -> name="" src=""
wx56027e6d27c2ef97 main=__APP__.wxapkg      hasConfig=true  -> name="" src=""
wx97a0053e10ef8083 main=__PLUGINCODE__.wxapkg hasConfig=false -> name="" src=""
wxae5e29812005203f main=__PLUGINCODE__.wxapkg hasConfig=false -> name="" src=""
```

---

## 2. 名称识别的整体思路

PR 的核心设计是**四层来源 + 置信度排序**：越靠前越可信，前一层拿到就直接返回，不再往下找。

```
                    ScanWxapkgItem(path, scan)
                              │
                              ▼
                 appNameForPathResult(path, wxid)
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
   ① readLocalAppName()              ② findMainWxapkg()
     本地元数据 JSON                    选主包
     source=local-metadata                  │
                                    readWxapkgAppNameResult()
                                            │
                          ┌─────────────────┼─────────────────┐
                          ▼                 ▼                 ▼
                  ③ app-config.json   ④ 代码候选        ②' 导航标题
                  source=             source=           source=
                  package-config      code-candidate    navigation-title
```

### 2.1 优先级与来源标记

| 优先级 | source 值 | UI 标签 | 数据来源 |
|---|---|---|---|
| 1（最高） | `local-metadata` | 本地元数据 | 微信客户端本地 `appinfo.json` 等 |
| 2 | `package-config` | 包内显式配置 | `app-config.json` 顶层/嵌套的 `appName`、`nickname`、`brandName` 等 |
| 3 | `navigation-title` | 全局导航标题 | `app-config.json` → `global.window.navigationBarTitleText` |
| 4（最低） | `code-candidate` | 代码候选（低置信度） | `app-service.js` 等文件中正则捕获的名称 |

### 2.2 关键代码路径

- 入口：`wechat/util.go` → `ScanWxapkgItem()`，对每个 `wx<16位hex>` 目录调用 `appNameForPathResult(localPath, dirName)`。
- 分支：`wechat/metadata.go` → `appNameForPathResult()`（957 行版本）。

```go
func appNameForPathResult(path, wxid string) appNameResult {
	if result := readLocalAppName(path, wxid); result.name != "" {  // ① 本地元数据
		return result
	}
	packagePath := findMainWxapkg(path)                              // ② 选主包
	if packagePath == "" {
		return appNameResult{}
	}
	result, err := readWxapkgAppNameResult(packagePath, wxid)
	if err != nil {
		return appNameResult{}                                       // ③ 注意：错误被静默吞掉
	}
	return result
}
```

> ⚠️ **可观测性问题**：`err` 被直接丢弃（`return appNameResult{}`），所以 UI 上无法区分「包里没有名称」和「包读取失败」，进一步增加了这次的排查难度。

### 2.3 主包选择（`findMainWxapkg`）

分三级策略，优先级从高到低：

1. **目录下直接有 `.wxapkg`** → `chooseMainWxapkg()`
2. **按版本子目录**（本机正是这种：`wx38ae.../168/__APP__.wxapkg`）→ 遍历子目录，按「最新 mtime → 版本号数值比较 → 路径字典序」排序取第一
3. **递归查找** → `ListFilesWithExtension(path, ".wxapkg")` 后同样按优先级排序

`chooseMainWxapkg` 的包名优先级：

```go
__app__.wxapkg         → 0
__full__.wxapkg        → 1
__subpackage__.wxapkg  → 2
其他                    → 3
__plugincode__.wxapkg  → 4   // 插件包，排最后
```

> 本机实测：`wx38ae5595accae89e/168/__APP__.wxapkg` ✅ 正确选中，说明**选包逻辑没问题**，问题在后面的解析。

### 2.4 wxapkg 解析（`readWxapkgAppNameResult`）

不把整个包读进内存，而是用 `wxapkgDataReader` 实现 `io.ReaderAt`，按需读取：

- **明文包**：直接映射文件偏移。
- **加密包**（微信 v4 默认）：前 6 字节跳过 → 用 `wxid` 派生 PBKDF2-SHA1 密钥（`saltiest` / 1000 轮）做 AES-CBC 解密前 1024 字节拿到「逻辑前缀」→ 之后的数据按 `xorKey = wxid[len-2]` 逐字节异或。
- 逻辑长度 = 物理长度 − 7（`encryptedRawOffsetDelta`）。

拿到 `logicalSize` 后，`parseWxapkgIndex()` 逐字段解析：

```
0xBE | info1(u32) | indexInfoLength(u32) | bodyInfoLength(u32) | 0xED | fileCount(u32)
     | { nameLen(u32) | name | offset(u32) | size(u32) } * fileCount
```

解析时做了完备的边界校验（这也正是 PR 标题 "harden" 的部分）：文件数上限 102400、文件名长度上限 1024、条目大小上限 10MB、`offset+size` 不得越界、文件名经 `normalizeArchiveEntryName()` 归一化并拒绝目录穿越。

> 本机实测：343 个条目解析成功，`app-config.json` 18660 字节可正常读出 —— **解析层也没问题**。

### 2.5 三个名称提取器

**A. `appNameFromConfigResult()`（包内配置）**

```go
// 1. 顶层直接查字段
appConfigNameFields = ["appName","miniProgramName","nickname",
                       "brandName","storeName","mallName","name","title"]
// 2. 依次下钻 global / app / appInfo / miniProgram
// 3. 兜底：global.window.navigationBarTitleText → navigation-title
```

字段匹配用 `strings.EqualFold`（大小写不敏感），值必须是 JSON `string`。

**B. `appNameFromCodeContent()`（代码候选）**

依次尝试 4 个正则，命中后经过 4 道过滤：

```go
codeNamePatterns = [
  // ① appId: "..." , appName: "捕获"
  appId["']?\s*[:=]\s*["'][^"']{4,64}["']\s*,\s*["']?appName["']?\s*[:=]\s*["']([^"'\r\n]{1,128})["']\s*,\s*["']?appVersion
  // ② appName: "捕获" , appVersion: "..." , appVersionCode:
  appName["']?\s*[:=]\s*["']([^"'\r\n]{1,128})["']\s*,\s*["']?appVersion["']?\s*[:=]\s*["'][^"']{1,64}["']\s*,\s*["']?appVersionCode["']?\s*[:=]
  // ③ authFloatInfo { ... name: "捕获"
  authFloatInfo\s*[:=]\s*\{[^}]{0,1000}\bname\s*[:=]\s*["']([^"'\r\n]{1,128})["']
  // ④ APPNAME = "捕获"
  \bAPPNAME\s*[:=]\s*["']([^"'\r\n]{1,128})["']
]
```

过滤链（任一不通过就换下一个正则）：
`cleanAppName()` 去空白 → `isGenericAppTitle()` 过滤「首页/我的/登录」等通用词 → 拒绝 wxid / 含 `/` `\` / `Netscape` / `Mozilla` → `isLikelyCodeName()` 要求 ≥4 个字符或含中文字符。

候选文件白名单 `codeNameFilePriority`：

```
common/vendor.js:0  app-service.js:1  app.js:2  common/app.js:3
common/main.js:4    main.js:5         vendor.js:6  manifest.js:7
```
（子目录同名文件优先级 +10，取最小优先级者）

**C. `appNameFromLocalConfig()`（本地元数据）**

查 `knownLocalMetadataFiles`：

```
appinfo.json, appInfo.json, app-info.json, info.json,
adapter-config.json, initial-rendering-cache-config.json
```

---

## 3. 失效根因详解（基于实测）

### 根因 1：`app-config.json` 里根本没有名称

实测本机 `wx38ae5595accae89e/168/__APP__.wxapkg` 中 `app-config.json` 的顶层键：

```
[componentFramework, pages, permission, plugins, tabBar, renderer,
 subPackages, entryPagePath, page, global, requiredPrivateInfos]
```

`global` 下只有一个键：`window`，其内容为：

```json
{"backgroundTextStyle":"light",
 "navigationBarBackgroundColor":"#fff",
 "navigationBarTextStyle":"black"}
```

逐条对照代码：

- `appConfigNameFields` 里的 8 个字段（`appName` / `nickname` / `brandName` …）→ ✅ 一个都不存在
- 下钻 `global` / `app` / `appInfo` / `miniProgram` → ✅ 全都不存在
- 兜底 `global.window.navigationBarTitleText` → ✅ **不存在**（`window` 里只有 3 个样式字段）

**结论**：`app-config.json` 在现代微信小程序里只描述路由与窗口样式，**不承载小程序名称**。名称是由微信客户端在本地维护的，不随代码包下发。

### 根因 2：代码候选正则零匹配

实测同一包的 `app-service.js`（1 322 462 字节）：

```
pattern 0: NO MATCH
pattern 1: NO MATCH
pattern 2: NO MATCH
pattern 3: NO MATCH
```

这四个正则都强依赖**特定的相邻字段排列**（如 `appId` + `appName` + `appVersion` 连续出现、或 `APPNAME =` 这种全大写常量），属于针对某些特定模板（如早期 uni-app / 特定 SDK 产物）的经验正则，**不具备普适性**。

不过同一文件里其实是有可用信号的：

```
nickName               = "Nickname"        ← 占位符，无用
nickname               = "Nickname"        ← 占位符，无用
navigationBarTitleText = "积分卡充值"       ← 真正的业务标题
```

也就是说：**代码里唯一可靠的信息是页面级 `navigationBarTitleText`，而代码候选机制恰恰只查 `app-config.json` 的 `global.window`，不查 JS 里的。**

### 根因 3：本地元数据白名单与实际不符 + MMKV 加密

实测 `local/wx38ae5595accae89e/` 的内容：

```
initial-rendering-cache-config.json   2 字节（内容为 {}）
mmkvadapterstorage/wx38ae5595accae89e 4096
usrmmkvstorage0/wx38ae5595accae89e    16384   ← 真实元数据在这里，二进制/加密
usrmmkvstorage1/wx38ae5595accae89e    16384
temp/*                                         ← 图片、字体
usr/miniprogramLog/log1
```

- 白名单里的 `appinfo.json` / `info.json` / `adapter-config.json` 在微信 **v4** 目录中**都不存在**（这些是 v3 时代的产物）。
- 唯一命中的 `initial-rendering-cache-config.json` 内容只有 `{}`，`json.Unmarshal` 得到空 map，直接返回空。
- 真实元数据在 MMKV 文件里，读取出来是加密二进制（实测主体为不可读字节），当前代码完全没有解析能力。

### 根因 4：`__PLUGINCODE__.wxapkg` 路径完全不覆盖

对 `wx97a0053e10ef8083`、`wxae5e29812005203f` 两个只有插件包的目录：

- `findMainWxapkg` 会选中 `__PLUGINCODE__.wxapkg`（优先级 4，但只有它）
- 该包**没有** `app-config.json`
- 也不含 `app-service.js` 这类在白名单里的文件
- 结果：必然为空

---

## 4. 为什么"重新 build 之后还是不行"

需要明确：**这不是构建问题，也不是补丁没打上**。可以从三个层面排除：

1. **补丁已正确落地**：`git apply` 干净应用，`go build ./...`、`go vet`、`go test ./wechat/`（20 个用例）全部通过；`wechat/metadata.go`、`wechat/core_test.go`、`third_party/jsbeautifier-go/` 均已在仓库中。
2. **Wails 绑定已同步**：`frontend/wailsjs/go/models.ts` 中 `WxapkgItem` 已包含 `AppName` / `AppNameSource` 字段，前端 `App.vue` 已渲染「识别名称」列。
3. **逻辑本身必然失败**：直接调用 `appNameForPathResult()` 读取本机真实包，返回 `name="" source=""` —— 与 UI 表现完全一致。

> 所以「build 之后还是没识别出来」是**该 PR 算法在真实数据上不成立**，而不是构建或集成的失误。

另外提醒一个容易踩的坑：如果只 `wails build` 而没有重新生成前端产物，`frontend/dist` 可能是旧的。但本例中 UI 明明显示了「未识别名称」占位文案，说明**前端新代码已经生效**，只是后端返回了空值 —— 这进一步印证了上面的结论。

---

## 5. 可行的改进方向（按性价比排序）

### 方向 A（推荐，成本最低）：从 JS 里提取 `navigationBarTitleText`

真实包里 `app-service.js` 明确存在 `navigationBarTitleText = "积分卡充值"`。建议在 `appNameFromCodeContent()` 中新增一个正则：

```go
regexp.MustCompile(`(?i)["']?navigationBarTitleText["']?\s*[:=]\s*["']([^"'\r\n]{1,128})["']`)
```

并注意两个坑：

- 必须先经过 `isGenericAppTitle()` 过滤，否则会大量命中「首页」「我的」「登录」等页面标题；
- 优先取**入口页**对应的标题，或选择出现频次最高的非通用标题，而不是第一个命中。

### 方向 B：解析微信 v4 的 MMKV 元数据

微信 v4 把小程序名称存在 `local/<wxid>/usrmmkvstorage*/<wxid>`（MMKV 格式）。需要：

- 实现 MMKV 容器解析（支持其 AES 加密模式），或
- 换用更稳的旁路：`icon/` 目录下按 wxid 命名的图标 + `data/<appid>/` 等目录中可能存在的名称痕迹。

成本较高，但这是**唯一能拿到官方名称**的来源。

### 方向 C：把 `__PLUGINCODE__.wxapkg` 纳入候选

当只有插件包时，至少要让它走一遍代码候选流程，而不是直接返回空。

### 方向 D：让失败可观测

修改 `appNameForPathResult`，把 `err` 通过 `AppNameSource`（如 `error`）或新字段透传到 UI，避免「静默吞错」导致无法定位。

### 方向 E：补测试，用真实包做回归

现有 `wechat/core_test.go` 的测试用例使用的是**合成包**（`testArchive()`），字段布局是测试自己构造的，因此无法暴露"真实包的 `app-config.json` 没有名称字段"这类问题。建议：

- 增加一个 `testdata/` 目录，放入脱敏后的真实 `__APP__.wxapkg` 片段；
- 对 `appNameForPathResult()` 做端到端断言。

---

## 6. 附：实测命令与结果

```powershell
# 1. 定位本机微信 v4 数据
$ap = "$env:APPDATA\Tencent\xwechat\radium\users\<userhash>\applet"

# 2. 包结构（本机实际）
#    packages/wx38ae5595accae89e/168/__APP__.wxapkg         3 049 597 B
#    packages/wx38ae5595accae89e/168/_package-user_.wxapkg  1 173 471 B
#    packages/wx38ae5595accae89e/168/_package-member-integral_.wxapkg 629 190 B

# 3. 用当前代码解析
#    主包选中：__APP__.wxapkg            ✅
#    索引解析：343 个条目               ✅
#    app-config.json：18 660 B 读出      ✅
#    名称提取：name="" source=""         ❌
```

---

## 7. 一句话总结

PR #62 的**工程加固部分（安全检查、并发、路径穿越防护、流式解包）质量很高且有效**，但**名称识别部分是基于错误假设的经验规则** —— 它假设小程序名称写在 `app-config.json` 或某几种特定代码模板里，而真实微信 v4 数据中两者都不成立。要真正识别名称，必须转向 JS 里的 `navigationBarTitleText` 或本地 MMKV 元数据。

---

## 8. 修复内容与验证结果

### 8.1 实际数据结构（重要更正）

修复过程中实测澄清了一个关键事实 —— 真实包里的标题字段**确实存在**，但位置与 PR 假设不同：

```
app-config.json
├── global.window          → 只有 3 个样式字段，无标题   ← PR 查这里，落空
├── entryPagePath          → "pages/full-screen/full-screen.html"
└── page["<page>.html"]    → { "window": { "navigationBarTitleText": "..." } }   ← 真正有标题
```

`page` 表是**每页**的 window 配置，共 106 / 294 条，绝大多数带 `navigationBarTitleText`。

### 8.2 修复点

| # | 修复 | 位置 |
|---|------|------|
| 1 | **入口页标题**：读 `app-config.json` 的 `entryPagePath`，再取 `page[entryPagePath].window.navigationBarTitleText` | `appNameFromEntryPageTitle()` |
| 2 | **标题投票兜底**：入口页无标题时，取出现次数 ≥2 的非通用页面标题（如「建发统一收银台」×6） | `appNameFromPageTitleVote()` |
| 3 | **代码层新增正则**：`navigationBarTitleText` 捕获，覆盖 `app-service.js` 场景 | `codeNamePatterns[4]` |
| 4 | **修正来源优先级**：代码正则结果不再压过结构化来源（`codeNamePriorityBase = 100`） | `codeEntryPriority()` |
| 5 | **小游戏支持**：新增 `project.json` / `game.json` 解析（`gameNamePriorityBase = 20`） | `appNameFromGameConfig()` |
| 6 | **插件包回退**：主包无名称时依次扫描其余包（含 `__PLUGINCODE__.wxapkg`） | `packageCandidates()` |
| 7 | **本地元数据白名单纠正**：移除内容恒为 `{}` 的 `initial-rendering-cache-config.json` | `knownLocalMetadataFiles` |
| 8 | 不再静默吞错：单包解析失败继续尝试下一个包 | `appNameForPathResult()` |

### 8.3 修复前后对比（本机真实数据）

| WxId | 修复前 | 修复后 | 来源 |
|------|--------|--------|------|
| `wx38ae5595accae89e` | （空） | **积分卡充值** | `code-candidate` |
| `wx56027e6d27c2ef97` | （空） | **建发统一收银台** | `navigation-title` |
| `wx3d52dd4807d5e0fa` | （空） | （空） | 小游戏，包内无名称 |
| `wx97a0053e10ef8083` | （空） | （空） | 纯插件包，无名称 |
| `wxae5e29812005203f` | （空） | （空） | 纯插件包，无名称 |

识别率：**0/5 → 2/5**。

`wx38ae5595accae89e` 走 `code-candidate` 而非 `navigation-title` 是**正确行为**：它的 9 个页面标题各只出现 1 次（「领取优惠券」「我的参与记录」…），属于页面标签而非程序名，因此配置层拒绝采用；而 `app-service.js` 里只有唯一的 `navigationBarTitleText`（「积分卡充值」），与 `app-config.json` 中 `pages/exchange/exchange.html` 的标题完全一致，是可靠的唯一候选。

### 8.4 剩余 3 个的说明

这三个**不是 bug**，而是包内确实没有名称数据：

- `wx3d52dd4807d5e0fa`：**小游戏**包。`app-config.json` 只有 `openDataContext` / `gamePlugins` 等游戏字段，无 `page` 表；`project.json` 内容为 `{"showFPS":true,"frameRate":60,...}`，**不含 `name`**。
- `wx97a0053e10ef8083` / `wxae5e29812005203f`：**插件包**（`__PLUGINCODE__.wxapkg`）。`plugin.json` 只有 `page`/`pages` 结构，页面标题为空字符串。

要覆盖这些情况，只能转向**方向 B（解析微信 v4 的 MMKV 元数据）**，成本较高。

### 8.5 验证

```
go build ./...        ✅
go vet ./wechat/      ✅
gofmt -l (改动文件)    ✅ 干净
go test ./wechat/     ✅ 28 个用例全部通过
```

新增测试覆盖：入口页标题优先、入口页标题压制其他页标题、重复标题投票、单次标题被忽略、小游戏配置解析、代码优先级低于结构化来源、游戏配置压制代码猜测、插件包纳入候选。

### 8.6 exe 重新构建

本机未安装 `wails` CLI，使用等价命令直接构建（前端产物 `frontend/dist` 已包含新列）：

```powershell
go build -tags desktop,production -ldflags "-H windowsgui -s -w" -o build\bin\wxapkg-gui.exe .
```

已验证新逻辑确实编入二进制（`navigation-title` / `code-candidate` / `package-config` / `local-metadata` 四个来源字符串均存在）。

---

## 9. 第二轮修复：分享卡片标题（share-card）

### 9.1 问题

第一轮修复后 `wx38ae5595accae89e` 被识别为「积分卡充值」，但它**真实名称是「湘潭铺子会员中心」**。

第一轮之所以"看起来成功"，是因为 `app-service.js` 里恰好只有一个 `navigationBarTitleText`（「积分卡充值」，来自 `pages/exchange/exchange.html` 兑换页），被当作唯一候选采用了 —— **实际上那是某个页面的标题，不是程序名称**。

### 9.2 真正的名称来源：分享回调

用户指出 `wxShareConfig` 的分享标题可以作为名称参考。实测确认，`app-service.js` 里存在：

```js
i.onShareAppMessage(function(){
    return i.index.$tracker.shareLog({...}),
    {title:"湘潭铺子会员活动", path:"/pages/brand-dynamics/brand-dynamics"}
}),

l.onShareAppMessage(function(){
    return l.index.$tracker.shareLog({...}),
    {title:"湘潭铺子会员中心", path:"/pages/index/index"}
})
```

**分享卡片标题正是用户转发小程序时看到的名字**，因此是最可靠的名称来源。全包中仅这 2 处出现品牌名，且其中指向首页（`/pages/index/index`）的那条就是程序名。

### 9.3 实测验证的其他字段（均无效）

为避免再次遗漏，我逐一实测了以下候选字段，在本包中**全部零命中或无值**：

```
brandName / mallName / storeName / shopName / companyName
shareTitle / shareDesc / defaultTitle / appTitle / siteName
tenantName / merchantName / orgName / corpName / wxName
__wxConfig / wxShareConfig / onAddToTimeline / setNavigationBarTitle
app-config.json 的 tabBar（custom:true，无文字标签）
app-config.json 的 plugins（只有 provider 与版本号）
```

结论：**该小程序包内唯一的名称信号就是分享回调的 `title`**。

### 9.4 修复实现

新增来源 `share-card`（优先级介于 `package-config` 与 `navigation-title` 之间）：

| 顺序 | 来源 | 说明 |
|---|---|---|
| 1 | `local-metadata` | 本地元数据 JSON |
| 2 | `package-config` | `app-config.json` 显式名称字段 |
| 3 | **`share-card`（新增）** | 分享回调 `{title, path}` |
| 4 | `navigation-title` | 入口页 / 全局导航标题 |
| 5 | `code-candidate` | 其他代码正则 |

关键设计：

- `shareTitlePattern` 匹配 `title: "...", path: "..."` **成对**出现，避免把任意 `title` 字段误当名称；
- `shareHomePathPattern` 识别指向首页的分享（`/pages/index|home|main|entry|app`），**首页分享标题优先**，因为它描述程序本身，而其他页面的分享常是活动文案；
- 无首页分享时，退回第一个可用标题（如「湘潭铺子会员活动」）；
- **过滤链**：拒绝通用标题（首页/我的…）、wxid、含 `/` `\`、营销文案（秒杀/限时/立即/抢购/领取…）、以及少于 4 字符且无中文的短串。

### 9.5 修复前后对比

| WxId | 第一轮（错误） | 第二轮（正确） |
|---|---|---|
| `wx38ae5595accae89e` | 积分卡充值（`code-candidate`）❌ | **湘潭铺子会员中心**（`share-card`）✅ |
| `wxae5e29812005203f` | （空） | （空）— 纯插件包，无名称 |

### 9.6 边界测试

| 输入 | 结果 | 说明 |
|---|---|---|
| `{title:"湘潭铺子会员中心",path:"/pages/index/index"}` | 采用 | 首页分享 |
| `{title:"湘潭铺子会员活动",path:"/pages/brand-dynamics/..."}` | 作为兜底 | 非首页 |
| 两者并存 | 采用「湘潭铺子会员中心」 | 首页优先 |
| `{title:"限时秒杀",path:"/pages/index/index"}` | 拒绝 | 营销文案 |
| `{title:"wx38ae5595accae89e",...}` | 拒绝 | wxid |
| `{title:"首页",...}` | 拒绝 | 通用标题 |
| `{title:"Costa Coffee",...}` | 采用 | 正常英文名 |

### 9.7 验证

```
go build ./...      ✅
go vet ./wechat/    ✅
gofmt（改动文件）    ✅ 干净
go test ./wechat/   ✅ 35 个用例全部通过（新增 7 个分享相关用例）
```

前端同步：`appNameSourceLabels` 新增 `'share-card': '分享卡片标题'`，tooltip 补充分享来源说明；已重新构建 `frontend/dist` 与 `build\bin\wxapkg-gui.exe`（已确认 `share-card` 编入二进制）。

### 9.8 说明

本轮**未使用** `applet.db`（按要求排除）。所有结论均来自 wxapkg 包内数据。

---

## 10. 第三轮修复：wxShare 分享标题（最高优先级）

### 10.1 问题

`wx56027e6d27c2ef97` 被识别为「建发统一收银台」，真实名称是**「建发钻石会会员中心」**。

### 10.2 完整提取顺序追踪（问题根源）

实测该小程序目录下共有 **7 个 wxapkg**（1 主包 + 5 子包 + 1 插件包）：

```
232\__APP__.wxapkg                → 建发统一收银台 (navigation-title)   ← 之前只扫这个
232\_pages_index_.wxapkg          → 建发钻石会会员中心 (wx-share)        ← 真正的名称
232\_pages__app_.wxapkg           → （空）
232\_pages_mall_.wxapkg           → 建发钻石会积分商城 (wx-share)
232\_pages_member-world_.wxapkg   → 建发钻石会会员天地 (wx-share)
232\_pages_user_.wxapkg           → （空）
22\__PLUGINCODE__.wxapkg          → （空）
```

问题有两层：

1. **只扫描了主包**：`__APP__.wxapkg` 里 `page` 表的 6 个「建发统一收银台」全是收银台/支付结果页标题（`pay` / `success` / `defeat` / `pay-common`），属于**功能模块名**，被标题投票选中。
2. **提前返回**：即使后来扫描了子包，`appNameForPathResult()` 遇到主包的非空结果就 `return`，永远走不到 `_pages_index_`。

### 10.3 真正的名称来源：wxShare

你指出的位置，实测精确定位于：

```
_pages_index_.wxapkg → pages/index/app-service.js @81084

wxShareConfig: function(){ this.wxShare({title:"建发钻石会会员中心"}) }
```

**这是开发者在首页显式声明的分享标题，就是程序名本身**，因此定为最高优先级。

同时发现需要区分的干扰项：

| 包 | wxShare 标题 | 性质 |
|---|---|---|
| `pages/index` | 建发钻石会会员中心 | ✅ 首页，程序名 |
| `pages/mall` | 建发钻石会积分商城 | 子模块名 |
| `pages/member-world` | 建发钻石会会员天地 | 子模块名 |
| `pages/mall` | `title:this.tagName` | 动态变量，非字面量，忽略 |

### 10.4 最终优先级

```
wx-share (60)  >  share-card (50)  >  poster-brand (40)
               >  package-config (20)  >  navigation-title (10)  >  code-candidate (0)
```

（`local-metadata` 仍为最高前置短路）

### 10.5 修复实现

| # | 修复 | 位置 |
|---|---|---|
| 1 | 新增 `wxSharePattern`：匹配 `wxShare({...title:"..."})`，支持包裹形式 | `metadata.go` |
| 2 | 新增来源 `wx-share`，跨包比较时**最高优先级** | `appNameFromWxShare()` |
| 3 | 用 `isHomeShareEntry()` 判定首页（`pages/index|home|main|entry|app`、顶层 `main.js`），**首页命中直接短路返回** | `isHomeShareEntry()` |
| 4 | **扫描全部子包**：`packageCandidates` 不再只看主包 | `packageCandidates()` |
| 5 | 子包排序：主包 → 首页子包 → 其他页面子包 → 插件包 | `packageScanPriority()` |
| 6 | **跨包择优**：收集所有包结果按 rank 取最优，不再首个非空即返回 | `appNameForPathResult()` |
| 7 | `navigation-title` 降级到游戏配置之后 | 两个扫描函数 |

### 10.6 三轮结果汇总

| WxId | 第一轮 | 第二轮 | **第三轮（最终）** |
|---|---|---|---|
| `wx38ae5595accae89e` | 积分卡充值 ❌ | 湘潭铺子会员中心 ✅ | **湘潭铺子会员中心**（`share-card`）✅ |
| `wx56027e6d27c2ef97` | 建发统一收银台 ❌ | 建发统一收银台 ❌ | **建发钻石会会员中心**（`wx-share`）✅ |
| `wx97a0053e10ef8083` | （空） | （空） | （空）— 纯插件包 |
| `wxae5e29812005203f` | （空） | （空） | （空）— 纯插件包 |

### 10.7 验证

```
go build ./...      ✅
go vet ./wechat/    ✅
gofmt               ✅ 干净
go test ./wechat/   ✅ 41 个用例全部通过（新增 6 个 wxShare 相关用例）
```

前端同步：`appNameSourceLabels` 新增 `wx-share` / `poster-brand` 两个标签，并区分各来源 tooltip；已重建 `frontend/dist` 与 `build\bin\wxapkg-gui.exe`（已确认 `wx-share` 编入二进制）。

### 10.8 关键教训

前两轮之所以反复出错，根本原因是**只看主包**。现代微信小程序把页面逻辑拆分到子包（`_pages_xxx_.wxapkg`），而程序名往往声明在首页子包中。现在扫描全部包并跨包择优，这类问题不会再出现。


