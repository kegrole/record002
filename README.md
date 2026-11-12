# xssscan — 纯标准库前端 DOM XSS 静态检测器

xssscan 只依赖 Python 标准库（html.parser + 手写的 JavaScript 词法/语法分析器），
对目录中的 .html / .js / .mjs 文件做静态污点分析，报告不可信 source 真正
可达危险 sink 的位置。

## 用法

    python -m xssscan.cli --root <待扫描目录> --out <输出 json 路径>

demo：

    python -m xssscan.cli --root demo_site --out out/findings.json

stdout 打印一行 JSON 摘要，例如：

    {"by_sink_type":{"innerHTML":2},"finding_count":10,"scanned_files":6}

## 输出格式

每条 finding 包含：

- file：sink 所在文件（相对扫描根的 POSIX 路径）
- sink_type：sink 类型标识（见下表）
- line / col：sink 关键字所在行列（均为 1-based）
- sources：可达该 sink 的 source 标签列表
- propagation_path：source 到 sink 的有序传播步骤，每步含 file 与 line

报告整体按 (file, line, col, sink_type, sources, path) 排序、键排序输出，
同一输入连续运行两次得到字节级一致的 JSON。

## Sink 清单

| sink_type | 触发形式 |
| --- | --- |
| innerHTML | el.innerHTML = 污点 |
| outerHTML | el.outerHTML = 污点 |
| insertAdjacentHTML | el.insertAdjacentHTML(pos, 污点)，取第 2 个参数 |
| document.write | document.write(...) / document.writeln(...) |
| eval | eval(污点) 或 window.eval(...) |
| new_function | new Function(..., 污点函数体)，取最后一个参数 |
| setTimeout | setTimeout(字符串污点, ms)，仅字符串首参，函数回调不报 |
| setInterval | setInterval(字符串污点, ms)，同上 |
| location_href | location.href = 污点、location = 污点、document.location = ... |
| window.open | window.open(污点 url) |
| postMessage | parent.postMessage(污点, ...) / top.postMessage(...) |
| event_attribute | HTML 中 on* 事件属性值内引用了 source，定位到元素所在行 |
| javascript_uri | href / src 为 javascript: 且其代码引用了 source |

textContent、dataset.* 等不执行 HTML 的赋值不是 sink，不会报告。

## Source 清单

| 标签 | 形式 |
| --- | --- |
| location.hash | location.hash、window.location.hash |
| location.search | location.search、window.location.search |
| location.href | location.href、window.location.href |
| document.URL | document.URL |
| document.referrer | document.referrer |
| event.data | message 事件回调中的 event.data（含 evt / e 等命名） |
| localStorage.getItem | localStorage.getItem(key) |
| URLSearchParams.get | new URLSearchParams(...).get(name) / getAll(name) |

## 传播规则

1. 跨语句：变量赋值携带污点；后续被固定字面量覆盖后旧污点失效，因此
   const x = "hello"; eval(x) 不报告。
2. 跨函数：实参污点传入形参，函数体内形参流入 sink 会在调用点记录；
   返回值同样把污点带回调用方。
3. 跨文件（ES Module）：export const x = source 经 import { x } 传递到
   另一个 .js 或 HTML 内联 module，传播路径同时包含两个文件。
4. 常量折叠：纯字面量参与的 +、一元运算、三元表达式折叠为常量；只要
   结果不含 source origin，流入 sink 也不报告。
5. 控制流合并：if/else、循环、try/catch、switch 中任一分支把变量变为
   污点，分支后该变量按污点处理（保守合并）。
6. 内建透传方法：trim、slice、replace、encodeURIComponent、toString、
   模板字符串等保留字符串污点。
7. HTML 入口：内联 script 的行列映射回宿主 HTML；on* 属性与 javascript:
   URI 单独作为 HTML sink 报告。

## 目录结构

    xssscan/
      html_parser.py   # 基于 html.parser 的脚本/事件属性/javascript: 抽取
      js_scanner.py    # 手写 JS 词法分析器 + 递归下降解析器（带行列位置）
      sinks.py         # sink 目录
      sources.py       # source 目录
      taint.py         # 值模型、作用域、污点传播与跨文件模块引擎
      report.py        # 目录遍历、HTML 编排、确定性 JSON 输出
      cli.py / __main__.py
    demo_site/         # 4 个页面 + 共享 JS 模块
    fixtures/          # 5 条验收样例
    tests/test_xssscan.py

## 测试

    python -m unittest test_xssscan -v

5 条验收口径（fixtures/ 中逐条对应）均有独立断言，并额外覆盖行列精度、
常量覆盖、跨函数/跨文件、控制流合并、URLSearchParams 与可复现性。
