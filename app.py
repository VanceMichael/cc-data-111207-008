import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

from collector import Collector
from reader import inspect, preview
from source import Mailbox


def load_fixture(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def command_preview(fixture: dict, assess: bool = False) -> dict:
    if assess:
        mailbox = Mailbox(fixture)
        return {
            "邮箱代次": mailbox.generation,
            "邮件": [preview_with_status(mailbox.fetch(uid), uid) for uid in sorted(mailbox.messages)],
        }
    return inspect(Mailbox(fixture), fixture)


def preview_with_status(raw, uid):
    from reader import assess

    result = assess(raw)
    result["uid"] = uid
    return result


def command_collect(fixture: dict, state: Path, fail_ack: bool, fault_stage: str | None) -> dict:
    mailbox = Mailbox(fixture)
    mailbox.fail_ack = fail_ack
    faults = []

    triggered = [False]

    def fault(stage, context):
        if fault_stage is None:
            return
        faults.append({"阶段": stage, "上下文": context})
        if fault_stage == stage and not triggered[0]:
            triggered[0] = True
            raise RuntimeError(f"注入故障: {stage}")

    with Collector(mailbox, state, fault=fault) as collector:
        summary = collector.collect()
    result = summary.as_dict()
    result["注入故障"] = faults
    result["处理标记"] = [
        {"邮箱世代": generation, "UID": uid}
        for generation, uid in sorted(mailbox.flags)
    ]
    return result


def command_attachments(state: Path, fixture: dict | None) -> list[dict]:
    with Collector(Mailbox(fixture or {"uidvalidity": 0, "messages": []}), state) as collector:
        rows = collector.db.execute(
            "SELECT a.id, a.original_filename, a.part_path, a.status, a.size, "
            "a.isolation_reason, d.uidvalidity, d.uid, d.message_id, d.receive_status "
            "FROM attachment a JOIN delivery d ON d.id = a.delivery_id "
            "ORDER BY d.uidvalidity, d.uid, a.ordinal"
        ).fetchall()
        return [dict(row) for row in rows]


def command_source(state: Path, attachment_id: int | None) -> dict:
    fixture = {"uidvalidity": 0, "messages": []}
    with Collector(Mailbox(fixture), state) as collector:
        if attachment_id is None:
            raise SystemExit("--source 需要附件编号")
        data = collector.attachment_source(attachment_id)
        if data is None:
            raise SystemExit(f"未找到附件编号 {attachment_id}")
        return data


def command_quarantine(state: Path) -> list[dict]:
    with Collector(Mailbox({"uidvalidity": 0, "messages": []}), state) as collector:
        return collector.isolated()


def command_status(state: Path) -> dict:
    with Collector(Mailbox({"uidvalidity": 0, "messages": []}), state) as collector:
        return collector.status()


def command_demo() -> dict:
    """演示 UID 重置、转发重投和确认失败，全程使用临时目录。"""
    fixture = load_fixture(Path(__file__).parent / "fixtures" / "source.json")
    root = Path(tempfile.mkdtemp(prefix="mail-demo-"))
    steps = []
    try:
        mailbox = Mailbox(fixture)
        mailbox.fail_ack = True
        with Collector(mailbox, root / "state", fault=None) as collector:
            summary = collector.collect()
            first = collector.delivery_source(1)
        steps.append(
            {
                "步骤": "首次采集，确认失败",
                "汇总": summary.as_dict(),
                "远端标记": len(mailbox.flags),
                "首封投递": first,
            }
        )

        mailbox.fail_ack = False
        with Collector(mailbox, root / "state") as collector:
            summary = collector.collect()
            recovered = collector.delivery_source(1)
        steps.append(
            {
                "步骤": "重启后补确认",
                "汇总": summary.as_dict(),
                "远端标记": len(mailbox.flags),
                "首封确认": recovered["远端确认"],
            }
        )

        # 同一 UID 转投另一份内容：不能覆盖旧投递。
        redelivered = fixture["messages"][0]["raw"].replace(
            "aWQsdmFsdWUKQSwxOAo=",  # 原始 base64 载荷：id,value\nA,18\n
            "aWQsdmFsdWUKQSwyMQo=",
        )
        mailbox.redeliver(11, redelivered)
        with Collector(mailbox, root / "state") as collector:
            summary = collector.collect()
            deliveries = collector.db.execute(
                "SELECT id, uid, message_fingerprint, superseded_at FROM delivery WHERE uid = 11"
            ).fetchall()
            ack = collector.db.execute(
                "SELECT status FROM receipt ORDER BY delivery_id DESC LIMIT 1"
            ).fetchone()
        steps.append(
            {
                "步骤": "转发重投同一 UID",
                "汇总": summary.as_dict(),
                "UID 11 的投递": [dict(row) for row in deliveries],
                "最新投递确认": ack["status"] if ack else None,
            }
        )

        # UIDVALIDITY 重建后，同一 UID 是另一封信。
        mailbox.reset(
            {
                11: "Message-ID: <another@example.invalid>\nMIME-Version: 1.0\n"
                "Content-Type: multipart/mixed; boundary=\"b\"\n\n--b\n"
                "Content-Type: text/csv\nContent-Disposition: attachment; filename=\"other.csv\"\n"
                "Content-Transfer-Encoding: base64\n\naix2YWx1ZQpCLDIK\n--b--\n"
            }
        )
        with Collector(mailbox, root / "state") as collector:
            summary = collector.collect()
            generations = collector.db.execute(
                "SELECT uidvalidity, uid, message_id, superseded_at FROM delivery ORDER BY id"
            ).fetchall()
        steps.append(
            {
                "步骤": "UIDVALIDITY 重建",
                "汇总": summary.as_dict(),
                "全部投递": [dict(row) for row in generations],
            }
        )
        return {"演示目录": str(root), "步骤": steps}
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="本地来源预览与授权邮箱附件采集")
    parser.add_argument(
        "--fixture", type=Path, default=Path(__file__).parent / "fixtures" / "source.json"
    )
    parser.add_argument(
        "--state", type=Path, default=Path(__file__).parent / "state",
        help="账本与内容存储目录；默认 state/",
    )
    parser.add_argument("--collect", action="store_true", help="批量采集附件")
    parser.add_argument("--assess", action="store_true", help="预览解析状态与隔离原因")
    parser.add_argument("--fail-ack", action="store_true", help="演示确认失败")
    parser.add_argument("--fault", choices=["after_blob_write", "before_ack"], help="注入故障阶段")
    parser.add_argument("--attachments", action="store_true", help="列出账本中的附件")
    parser.add_argument("--source", type=int, metavar="附件编号", help="查询附件来源")
    parser.add_argument("--quarantine", action="store_true", help="列出隔离附件")
    parser.add_argument("--ledger", action="store_true", help="查看账本计数")
    parser.add_argument("--demo", action="store_true", help="运行 UID 重置与确认失败演示")
    arguments = parser.parse_args(argv)

    fixture_path = arguments.fixture
    fixture = load_fixture(fixture_path)

    if arguments.demo:
        data = command_demo()
    elif arguments.source is not None:
        data = command_source(arguments.state, arguments.source)
    elif arguments.quarantine:
        data = command_quarantine(arguments.state)
    elif arguments.ledger:
        data = command_status(arguments.state)
    elif arguments.attachments:
        data = command_attachments(arguments.state, fixture)
    elif arguments.collect:
        data = command_collect(fixture, arguments.state, arguments.fail_ack, arguments.fault)
    elif arguments.assess:
        data = command_preview(fixture, assess=True)
    else:
        data = command_preview(fixture)
    json.dump(data, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
