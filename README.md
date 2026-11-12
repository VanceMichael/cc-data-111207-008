# 邮箱附件采集的身份重置与可追溯接收

本工具用于查看授权来源的数据及其原始边界，样例中的机构、设备、人员和标识均为
虚构。原有入口提供来源预览；新增的采集入口把一次邮件投递是否接收成功与它的附件
是否已写入存储关联起来，可重复运行并可从中断处恢复。

## 目录

- `source.py`：可注入故障的本地邮箱适配器（UIDVALIDITY、确认失败、重投、重建）
- `reader.py`：原有预览 `preview`/`inspect`，以及带隔离原因的 `assess`
- `mime_parse.py`：纯解析层，产出附件候选与隔离原因
- `collector.py`：内容寻址存储、接收账本、确认与崩溃恢复
- `app.py`：预览、批量采集、来源查询与演示入口
- `fixtures/source.json`：合成邮件和邮箱元数据，可替换为同结构样例
- `docs/数据约定.md`：接口、身份规则、隔离原因与恢复顺序

## 运行

使用 Python 3.11 及标准库，无第三方依赖。

```bash
python3 app.py                 # 原有预览
python3 app.py --assess        # 预览部件路径、状态与隔离原因
python3 app.py --collect       # 批量采集到 state/
python3 app.py --source 2      # 查询附件 2 的投递来源与共用内容
python3 app.py --quarantine    # 列出隔离附件及原因
python3 app.py --demo          # 在临时目录演示重投、UID 重置与确认失败
python3 -m unittest discover -s tests -v
PYTHONPYCACHEPREFIX=/tmp/collector-pycache python3 -m compileall -q app.py reader.py source.py mime_parse.py collector.py tests
```

存储与账本写入 `state/`（可用 `--state` 指定其他目录），不会写回样例文件。

## 关键行为

- 邮件身份 = 邮箱 + UIDVALIDITY + UID + 原始字节 SHA-256；Message-ID 和主题
  只用于展示。UIDVALIDITY 改变后，同一 UID 作为新投递入账，旧世代数据保留。
- 附件按内容摘要存放，多条投递可以共用同一份字节，但每条投递仍有独立来源行；
  同名不同内容不会被覆盖。
- 磁盘路径只由摘要生成。发件人提供的文件名只作为账本元数据。
- 转发邮件（message/rfc822）、嵌套 multipart、编码文件名、内联图片和空附件
  都会被解析并记录 MIME 部件路径。
- 损坏附件进入隔离区并给出原因；整封状态变为 `partial`，不会确认远端标记，
  其余附件仍可用。
- 大附件、嵌套过深、部件过多和不支持的传输编码受 `Limits` 限制；被截断的
  邮件不会声称完整接收。
- 附件落盘、账本提交、远端确认分三步完成。重启后补写缺失内容、重试确认，
  并识别“远端已标记但本地未记录”的情况；不会重复发布附件或重复确认。

## 容器

基础镜像固定摘要，不在启动阶段安装软件或获取远程数据。

```bash
docker build --pull=false -t mail-attachments:local .
docker run --rm --network none mail-attachments:local
docker run --rm --network none mail-attachments:local python3 -m unittest discover -s tests -v
```

## 本机演示

在全新临时目录执行 `python3 app.py --demo` 可依次观察：确认失败后重启补确认、
同一 UID 被重投另一份内容、以及 UIDVALIDITY 重建后旧附件来源仍可查。演示使用
本地小尺寸合成材料，数秒结束，不需要账户、设备或外部站点。
