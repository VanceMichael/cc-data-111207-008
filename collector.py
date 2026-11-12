"""面向授权邮箱的附件采集账本。

设计边界：

* 邮件身份 = 邮箱名 + UIDVALIDITY 世代 + UID + 原始字节指纹。Message-ID
  和主题只作展示，不参与唯一性判断；UIDVALIDITY 改变后同一个 UID 会被
  记成另一封邮件，旧世代的数据原样保留。
* 内容按 SHA-256 存放，文件名只存在账本里。磁盘路径永远由内容摘要生
  成，不使用发件人提供的任何路径片段。
* 附件字节先写入内容存储，再提交账本；两者没有共同事务。提交成功后
  才向邮箱写处理标记，标记失败会留下可重试的接收凭据。
* 恢复流程只补写缺失内容、重试确认，或把已失效的凭据标记为 stale；
  它不会重新发布已经入账的附件。
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from mime_parse import Limits, parse_message


SCHEMA = """
CREATE TABLE IF NOT EXISTS generation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    UNIQUE (mailbox, uidvalidity)
);

CREATE TABLE IF NOT EXISTS content (
    hash TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS delivery (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox TEXT NOT NULL,
    generation_id INTEGER NOT NULL REFERENCES generation(id),
    uidvalidity INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    message_fingerprint TEXT NOT NULL,
    message_id TEXT,
    subject TEXT,
    sender TEXT,
    raw_size INTEGER NOT NULL,
    parse_status TEXT NOT NULL,
    receive_status TEXT NOT NULL,
    reason TEXT,
    detail TEXT,
    first_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    superseded_at TEXT,
    UNIQUE (generation_id, uid, message_fingerprint)
);

CREATE TABLE IF NOT EXISTS attachment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id INTEGER NOT NULL REFERENCES delivery(id),
    part_path TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    original_filename TEXT,
    raw_content_disposition TEXT,
    content_type TEXT,
    disposition TEXT,
    content_id TEXT,
    size INTEGER,
    status TEXT NOT NULL,
    isolation_reason TEXT,
    isolation_detail TEXT,
    content_hash TEXT REFERENCES content(hash),
    published_at TEXT,
    UNIQUE (delivery_id, part_path)
);

CREATE TABLE IF NOT EXISTS receipt (
    delivery_id INTEGER PRIMARY KEY REFERENCES delivery(id),
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    confirmed_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    delivery_id INTEGER,
    attachment_id INTEGER,
    detail TEXT
);

CREATE INDEX IF NOT EXISTS delivery_uid ON delivery(mailbox, uidvalidity, uid);
CREATE INDEX IF NOT EXISTS attachment_delivery ON attachment(delivery_id);
CREATE INDEX IF NOT EXISTS attachment_content ON attachment(content_hash);
CREATE INDEX IF NOT EXISTS receipt_status ON receipt(status);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ContentStore:
    """仅以内容摘要命名文件的追加式存储。"""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    @staticmethod
    def _validate(hash_value: str) -> str:
        if len(hash_value) != 64:
            raise ValueError("内容摘要长度不正确")
        int(hash_value, 16)  # 非十六进制会抛 ValueError
        return hash_value

    def path_for(self, hash_value: str) -> Path:
        hash_value = self._validate(hash_value)
        # 扁平目录即可；路径中没有发件人可控的字符。
        return self.root / hash_value

    def exists(self, hash_value: str, expected_size: int | None = None) -> bool:
        path = self.path_for(hash_value)
        if not path.is_file():
            return False
        if expected_size is not None:
            return path.stat().st_size == expected_size
        return True

    def write(self, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        destination = self.path_for(digest)
        if self.exists(digest, len(data)):
            return digest
        handle = tempfile.NamedTemporaryFile(
            mode="wb", dir=self.root, prefix=".tmp-", delete=False
        )
        try:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
            os.chmod(handle.name, 0o600)
            os.replace(handle.name, destination)
        except BaseException:
            handle.close()
            try:
                os.unlink(handle.name)
            except OSError:
                pass
            raise
        return digest

    def read(self, hash_value: str) -> bytes:
        return self.path_for(hash_value).read_bytes()


@dataclass
class _Outcome:
    fingerprint: str
    duplicate: bool
    superseded: bool = False


@dataclass
class CollectSummary:
    mailbox: str
    generation: int
    uidvalidity: int
    collected: list[int]
    duplicates: int
    superseded: int
    received: int
    partial: int
    rejected: int
    confirmed: int
    confirm_failed: int
    stale: int
    repaired: int = 0

    def as_dict(self) -> dict:
        return {
            "邮箱": self.mailbox,
            "邮箱代次": self.uidvalidity,
            "本次读取 UID": self.collected,
            "重复投递": self.duplicates,
            "被新版本替换": self.superseded,
            "接收成功": self.received,
            "部分接收": self.partial,
            "拒绝接收": self.rejected,
            "已确认": self.confirmed,
            "确认失败": self.confirm_failed,
            "失效凭据": self.stale,
            "补写内容": self.repaired,
        }


class Collector:
    def __init__(
        self,
        mailbox,
        state_dir: Path,
        mailbox_name: str = "local",
        limits: Limits | None = None,
        fault: Callable[[str, dict], None] | None = None,
    ):
        self.mailbox = mailbox
        self.mailbox_name = mailbox_name
        self.limits = limits or Limits()
        self.fault = fault
        state_dir = Path(state_dir)
        state_dir.mkdir(parents=True, exist_ok=True)
        self.store = ContentStore(state_dir / "content")
        self.db = sqlite3.connect(state_dir / "ledger.sqlite3")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA journal_mode = WAL")
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @contextmanager
    def _transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield self.db
        except BaseException:
            self.db.rollback()
            raise
        else:
            self.db.commit()

    def _event(self, event_type, delivery_id=None, attachment_id=None, detail=None):
        self.db.execute(
            "INSERT INTO ledger_event (at, event_type, delivery_id, attachment_id, detail) VALUES (?,?,?,?,?)",
            (now(), event_type, delivery_id, attachment_id, detail),
        )

    def _inject(self, stage: str, context: dict) -> None:
        if self.fault:
            self.fault(stage, context)

    def _ensure_generation(self, uidvalidity: int) -> int:
        with self._transaction() as db:
            row = db.execute(
                "SELECT id FROM generation WHERE mailbox = ? AND uidvalidity = ?",
                (self.mailbox_name, uidvalidity),
            ).fetchone()
            if row:
                return row["id"]
            cursor = db.execute(
                "INSERT INTO generation (mailbox, uidvalidity, first_seen) VALUES (?,?,?)",
                (self.mailbox_name, uidvalidity, now()),
            )
            self._event(
                "generation_opened",
                detail=f"uidvalidity={uidvalidity}",
            )
            return cursor.lastrowid

    def collect(self) -> CollectSummary:
        generation, uids = self.mailbox.list_uids()
        generation_id = self._ensure_generation(generation)
        stale = self._retire_stale_receipts(generation)
        # 先补记“远端已标记、本地未记录”的确认事实，再处理未确认项。
        self._reconcile_mailbox_flags(generation)

        summary = CollectSummary(
            mailbox=self.mailbox_name,
            generation=generation_id,
            uidvalidity=generation,
            collected=sorted(uids),
            duplicates=0,
            superseded=0,
            received=0,
            partial=0,
            rejected=0,
            confirmed=0,
            confirm_failed=0,
            stale=0,
        )

        for uid in sorted(uids):
            outcome = self._collect_one(generation, generation_id, uid)
            delivery = self._delivery_for(generation_id, uid, outcome.fingerprint)
            if outcome.duplicate:
                summary.duplicates += 1
            if outcome.superseded:
                summary.superseded += 1
            status = delivery["receive_status"] if delivery else None
            if status == "received":
                summary.received += 1
            elif status == "partial":
                summary.partial += 1
            elif status == "rejected":
                summary.rejected += 1

        summary.stale = stale
        confirmed, failed, stale, repaired = self._recover_receipts(generation)
        summary.confirmed = confirmed
        summary.confirm_failed = failed
        summary.stale += stale
        summary.repaired = repaired
        return summary

    def _delivery_for(self, generation_id: int, uid: int, fingerprint: str | None):
        if not fingerprint:
            return None
        return self.db.execute(
            "SELECT * FROM delivery WHERE generation_id = ? AND uid = ? AND message_fingerprint = ?",
            (generation_id, uid, fingerprint),
        ).fetchone()

    def _collect_one(self, uidvalidity: int, generation_id: int, uid: int) -> "_Outcome":
        raw = self.mailbox.fetch(uid)
        fingerprint = hashlib.sha256(raw).hexdigest()

        existing = self._delivery_for(generation_id, uid, fingerprint)
        if existing:
            # 已入账的投递不会被重新发布；确认由本轮末尾的统一恢复流程处理。
            return _Outcome(fingerprint=fingerprint, duplicate=True)

        parsed = parse_message(raw, self.limits)
        prepared: list[tuple] = []
        for ordinal, candidate in enumerate(parsed.attachments):
            content_hash = None
            if candidate.status == "ready" and candidate.content is not None:
                content_hash = self.store.write(candidate.content)
            prepared.append((ordinal, candidate, content_hash))

        self._inject(
            "after_blob_write",
            {"uid": uid, "fingerprint": fingerprint, "attachments": len(prepared)},
        )

        receive_status = {
            "complete": "received",
            "partial": "partial",
            "rejected": "rejected",
        }[parsed.status]
        receipt_status = "pending" if receive_status == "received" else "blocked"

        superseded = 0
        with self._transaction() as db:
            previous = db.execute(
                "SELECT id, message_fingerprint FROM delivery "
                "WHERE generation_id = ? AND uid = ? AND superseded_at IS NULL",
                (generation_id, uid),
            ).fetchall()
            for row in previous:
                if row["message_fingerprint"] != fingerprint:
                    db.execute(
                        "UPDATE delivery SET superseded_at = ?, updated_at = ? WHERE id = ?",
                        (now(), now(), row["id"]),
                    )
                    self._event(
                        "delivery_superseded",
                        delivery_id=row["id"],
                        detail=f"uid={uid} 的内容已被 {fingerprint[:12]} 取代",
                    )
                    superseded += 1

            for _, candidate, content_hash in prepared:
                if content_hash is not None:
                    db.execute(
                        "INSERT OR IGNORE INTO content (hash, size, created_at) VALUES (?,?,?)",
                        (content_hash, candidate.size, now()),
                    )

            cursor = db.execute(
                "INSERT INTO delivery (mailbox, generation_id, uidvalidity, uid, "
                "message_fingerprint, message_id, subject, sender, raw_size, "
                "parse_status, receive_status, reason, detail, first_seen, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    self.mailbox_name,
                    generation_id,
                    uidvalidity,
                    uid,
                    fingerprint,
                    parsed.message_id,
                    parsed.subject,
                    parsed.sender,
                    parsed.raw_size,
                    parsed.status,
                    receive_status,
                    parsed.reason,
                    parsed.detail,
                    now(),
                    now(),
                ),
            )
            delivery_id = cursor.lastrowid
            self._event(
                "delivery_ingested",
                delivery_id=delivery_id,
                detail=f"uid={uid} fingerprint={fingerprint[:12]} status={receive_status}",
            )

            for ordinal, candidate, content_hash in prepared:
                attachment_cursor = db.execute(
                    "INSERT INTO attachment (delivery_id, part_path, ordinal, "
                    "original_filename, raw_content_disposition, content_type, "
                    "disposition, content_id, size, status, isolation_reason, "
                    "isolation_detail, content_hash, published_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        delivery_id,
                        candidate.part_path,
                        ordinal,
                        candidate.original_filename,
                        candidate.raw_content_disposition,
                        candidate.content_type,
                        candidate.disposition,
                        candidate.content_id,
                        candidate.size,
                        "stored" if content_hash is not None else "isolated",
                        candidate.isolation_reason,
                        candidate.isolation_detail,
                        content_hash,
                        now() if content_hash is not None else None,
                    ),
                )
                attachment_id = attachment_cursor.lastrowid
                if content_hash is not None:
                    self._event(
                        "attachment_published",
                        delivery_id=delivery_id,
                        attachment_id=attachment_id,
                        detail=f"{candidate.part_path} {content_hash[:12]}",
                    )
                else:
                    self._event(
                        "attachment_isolated",
                        delivery_id=delivery_id,
                        attachment_id=attachment_id,
                        detail=candidate.isolation_reason or "unknown",
                    )

            db.execute(
                "INSERT INTO receipt (delivery_id, status, attempts, last_error, confirmed_at, updated_at) "
                "VALUES (?,?,?,?,?,?)",
                (delivery_id, receipt_status, 0, None, None, now()),
            )
        # 内容写入、账本提交和远端标记分属三个步骤，没有共同事务。
        # 本轮不确认，统一由 collect() 末尾的恢复流程处理，这样一次重试
        # 只对应一次远端调用，重启后的行为也一致。

        return _Outcome(
            fingerprint=fingerprint, duplicate=False, superseded=superseded > 0
        )

    def _attempt_ack(self, delivery_row) -> bool:
        return self._ack(delivery_row["id"], delivery_row["uidvalidity"], delivery_row["uid"])

    def _ack(self, delivery_id: int, uidvalidity: int, uid: int) -> bool:
        try:
            self.mailbox.acknowledge(uidvalidity, uid)
        except Exception as error:
            with self._transaction() as db:
                db.execute(
                    "UPDATE receipt SET status = ?, attempts = attempts + 1, "
                    "last_error = ?, updated_at = ? WHERE delivery_id = ?",
                    ("failed", f"{type(error).__name__}: {error}", now(), delivery_id),
                )
                self._event(
                    "ack_failed",
                    delivery_id=delivery_id,
                    detail=f"{type(error).__name__}: {error}",
                )
            return False
        self._inject(
            "after_ack_before_receipt", {"delivery_id": delivery_id, "uid": uid}
        )
        self._record_confirmed(delivery_id)
        return True

    def _record_confirmed(self, delivery_id: int) -> None:
        with self._transaction() as db:
            db.execute(
                "UPDATE receipt SET status = 'confirmed', attempts = attempts + 1, "
                "last_error = NULL, confirmed_at = ?, updated_at = ? WHERE delivery_id = ?",
                (now(), now(), delivery_id),
            )
            self._event("ack_confirmed", delivery_id=delivery_id)

    def _reconcile_mailbox_flags(self, generation: int) -> None:
        """远端标记已存在但账本仍是 pending/failed 时，补记确认事实。

        只有“本地内容已落账”且“远端里这个世代+UID 的标记确实存在”才认定
        为已确认；不会因为标记存在就发布未入账的附件。
        """
        known = getattr(self.mailbox, "flags", None)
        if known is None:
            return
        rows = self.db.execute(
            "SELECT d.id, d.uid FROM receipt r JOIN delivery d ON d.id = r.delivery_id "
            "WHERE d.mailbox = ? AND d.uidvalidity = ? AND r.status IN ('pending','failed')",
            (self.mailbox_name, generation),
        ).fetchall()
        for row in rows:
            if (generation, row["uid"]) not in known:
                continue
            with self._transaction() as db:
                db.execute(
                    "UPDATE receipt SET status = 'confirmed', last_error = NULL, "
                    "confirmed_at = ?, updated_at = ? WHERE delivery_id = ?",
                    (now(), now(), row["id"]),
                )
                self._event(
                    "ack_reconciled",
                    delivery_id=row["id"],
                    detail="远端标记已存在，补齐本地确认记录",
                )

    def _retire_stale_receipts(self, current_generation: int) -> int:
        rows = self.db.execute(
            "SELECT r.delivery_id, d.uid, d.uidvalidity FROM receipt r "
            "JOIN delivery d ON d.id = r.delivery_id "
            "WHERE d.mailbox = ? AND d.uidvalidity != ? AND r.status IN ('pending','failed','stale')",
            (self.mailbox_name, current_generation),
        ).fetchall()
        if not rows:
            return 0
        retired = 0
        with self._transaction() as db:
            for row in rows:
                if db.execute(
                    "SELECT status FROM receipt WHERE delivery_id = ?",
                    (row["delivery_id"],),
                ).fetchone()["status"] == "stale":
                    continue
                db.execute(
                    "UPDATE receipt SET status = 'stale', last_error = ?, updated_at = ? "
                    "WHERE delivery_id = ?",
                    (
                        "邮箱 UIDVALIDITY 已变化，旧世代标记不再适用",
                        now(),
                        row["delivery_id"],
                    ),
                )
                self._event(
                    "ack_stale",
                    delivery_id=row["delivery_id"],
                    detail=f"uidvalidity {row['uidvalidity']} -> {current_generation}",
                )
                retired += 1
        return retired

    def _recover_receipts(self, current_generation: int) -> tuple[int, int, int, int]:
        rows = self.db.execute(
            "SELECT d.* FROM receipt r JOIN delivery d ON d.id = r.delivery_id "
            "WHERE d.mailbox = ? AND d.uidvalidity = ? "
            "AND r.status IN ('pending','failed','blocked','confirmed') "
            "AND d.superseded_at IS NULL",
            (self.mailbox_name, current_generation),
        ).fetchall()
        confirmed = 0
        failed = 0
        stale = 0
        repaired = 0
        for delivery in rows:
            receipt = self.db.execute(
                "SELECT status FROM receipt WHERE delivery_id = ?", (delivery["id"],)
            ).fetchone()
            if receipt["status"] in {"confirmed", "blocked"}:
                # 已确认或已判定为部分接收的投递不调用远端标记：
                # 前者避免重复确认，后者不允许把不完整邮件标成已处理。
                repaired += max(0, self._repair_missing(delivery))
                continue
            repaired += max(0, self._repair_missing(delivery))
            if self._receipt_is_blocked(delivery["id"]):
                # 内容缺失且补写失败：本轮无法证明附件齐全，不确认。
                failed += 1
                continue
            self._inject(
                "before_ack",
                {
                    "delivery_id": delivery["id"],
                    "uid": delivery["uid"],
                    "uidvalidity": delivery["uidvalidity"],
                },
            )
            if self._attempt_ack(delivery):
                confirmed += 1
            else:
                receipt = self.db.execute(
                    "SELECT status FROM receipt WHERE delivery_id = ?",
                    (delivery["id"],),
                ).fetchone()
                if receipt and receipt["status"] == "stale":
                    stale += 1
                else:
                    failed += 1
        return confirmed, failed, stale, repaired

    def _repair_missing(self, delivery) -> int:
        """补写缺失内容，返回成功补写的附件数；无法修复时返回 -1。

        内容缺失不影响其余附件；只有无法证明内容完整时，receipt 会被
        标成 failed，本轮不会向远端确认。
        """
        missing = self.db.execute(
            "SELECT id, content_hash, size, part_path FROM attachment "
            "WHERE delivery_id = ? AND status = 'stored' AND content_hash IS NOT NULL",
            (delivery["id"],),
        ).fetchall()
        absent = [
            row
            for row in missing
            if not self.store.exists(row["content_hash"], row["size"])
        ]
        if not absent:
            return 0

        try:
            raw = self.mailbox.fetch(delivery["uid"])
        except Exception:
            self._set_receipt_failed(delivery["id"], "内容缺失且无法重新读取邮件")
            return -1
        if hashlib.sha256(raw).hexdigest() != delivery["message_fingerprint"]:
            self._set_receipt_failed(
                delivery["id"], "同一 UID 的邮件内容已变化，不能按旧凭据补写"
            )
            return -1

        parsed = parse_message(raw, self.limits)
        by_path = {item.part_path: item for item in parsed.attachments}
        repaired = 0
        for row in absent:
            candidate = by_path.get(row["part_path"])
            if (
                candidate is None
                or candidate.status != "ready"
                or candidate.content is None
            ):
                continue
            digest = self.store.write(candidate.content)
            if digest != row["content_hash"] or len(candidate.content) != row["size"]:
                continue
            with self._transaction() as db:
                db.execute(
                    "INSERT OR IGNORE INTO content (hash, size, created_at) VALUES (?,?,?)",
                    (digest, row["size"], now()),
                )
                db.execute(
                    "UPDATE attachment SET published_at = ?, status = 'stored' WHERE id = ?",
                    (now(), row["id"]),
                )
                self._event(
                    "content_repaired",
                    delivery_id=delivery["id"],
                    attachment_id=row["id"],
                    detail=digest[:12],
                )
            repaired += 1
        if repaired != len(absent):
            self._set_receipt_failed(delivery["id"], "部分附件内容缺失且无法修复")
            return -1
        return repaired

    def _set_receipt_failed(self, delivery_id: int, message: str) -> None:
        # blocked 表示本地内容无法自证完整，不能重试远端确认；failed 只表示
        # 远端确认失败，可以重试。已经确认过的投递保持 confirmed，只记事件。
        with self._transaction() as db:
            current = db.execute(
                "SELECT status FROM receipt WHERE delivery_id = ?", (delivery_id,)
            ).fetchone()["status"]
            if current != "confirmed":
                db.execute(
                    "UPDATE receipt SET status = 'blocked', last_error = ?, updated_at = ? "
                    "WHERE delivery_id = ?",
                    (message, now(), delivery_id),
                )
            self._event("recovery_failed", delivery_id=delivery_id, detail=message)

    def _receipt_is_blocked(self, delivery_id: int) -> bool:
        return (
            self.db.execute(
                "SELECT status FROM receipt WHERE delivery_id = ?", (delivery_id,)
            ).fetchone()["status"]
            == "blocked"
        )

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------

    def _attachment_rows(self, delivery_id: int):
        return self.db.execute(
            "SELECT * FROM attachment WHERE delivery_id = ? ORDER BY ordinal",
            (delivery_id,),
        ).fetchall()

    def _receipt_row(self, delivery_id: int):
        return self.db.execute(
            "SELECT * FROM receipt WHERE delivery_id = ?", (delivery_id,)
        ).fetchone()

    def _events(self, delivery_id: int):
        return self.db.execute(
            "SELECT at, event_type, attachment_id, detail FROM ledger_event "
            "WHERE delivery_id = ? ORDER BY id",
            (delivery_id,),
        ).fetchall()

    def delivery_source(self, delivery_id: int) -> dict | None:
        delivery = self.db.execute(
            "SELECT d.*, g.mailbox AS generation_mailbox FROM delivery d "
            "JOIN generation g ON g.id = d.generation_id WHERE d.id = ?",
            (delivery_id,),
        ).fetchone()
        if delivery is None:
            return None
        receipt = self._receipt_row(delivery_id)
        attachments = []
        for row in self._attachment_rows(delivery_id):
            attachments.append(self._attachment_dict(row))
        return {
            "投递编号": delivery["id"],
            "邮箱": delivery["mailbox"],
            "邮箱世代": delivery["uidvalidity"],
            "UID": delivery["uid"],
            "邮件指纹": delivery["message_fingerprint"],
            "Message-ID": delivery["message_id"],
            "主题": delivery["subject"],
            "发件人": delivery["sender"],
            "原始字节数": delivery["raw_size"],
            "解析状态": delivery["parse_status"],
            "接收状态": delivery["receive_status"],
            "未完整原因": delivery["reason"],
            "说明": delivery["detail"],
            "首次入账": delivery["first_seen"],
            "最近更新": delivery["updated_at"],
            "已被取代": delivery["superseded_at"],
            "远端确认": {
                "状态": receipt["status"] if receipt else None,
                "尝试次数": receipt["attempts"] if receipt else 0,
                "最近错误": receipt["last_error"] if receipt else None,
                "确认时间": receipt["confirmed_at"] if receipt else None,
            },
            "附件": attachments,
            "账本事件": [dict(row) for row in self._events(delivery_id)],        }

    def _attachment_dict(self, row) -> dict:
        shared = 0
        if row["content_hash"]:
            shared = self.db.execute(
                "SELECT COUNT(*) FROM attachment WHERE content_hash = ?",
                (row["content_hash"],),
            ).fetchone()[0]
        return {
            "附件编号": row["id"],
            "MIME 部件路径": row["part_path"],
            "原始文件名": row["original_filename"],
            "原始 Content-Disposition": row["raw_content_disposition"],
            "内容类型": row["content_type"],
            "处置": row["disposition"],
            "Content-ID": row["content_id"],
            "大小": row["size"],
            "状态": row["status"],
            "隔离原因": row["isolation_reason"],
            "隔离说明": row["isolation_detail"],
            "内容摘要": row["content_hash"],
            "存储路径": (
                str(self.store.path_for(row["content_hash"]))
                if row["content_hash"]
                else None
            ),
            "共用该内容的附件数": shared,
            "发布时间": row["published_at"],
        }

    def attachment_source(self, attachment_id: int) -> dict | None:
        row = self.db.execute(
            "SELECT * FROM attachment WHERE id = ?", (attachment_id,)
        ).fetchone()
        if row is None:
            return None
        delivery = self.db.execute(
            "SELECT * FROM delivery WHERE id = ?", (row["delivery_id"],)
        ).fetchone()
        result = {
            "附件": self._attachment_dict(row),
            "投递": {
                "投递编号": delivery["id"],
                "邮箱": delivery["mailbox"],
                "邮箱世代": delivery["uidvalidity"],
                "UID": delivery["uid"],
                "邮件指纹": delivery["message_fingerprint"],
                "Message-ID": delivery["message_id"],
                "接收状态": delivery["receive_status"],
                "接收原因": delivery["reason"],
            },
        }
        if row["content_hash"]:
            peers = self.db.execute(
                "SELECT a.id, a.part_path, a.original_filename, d.id AS delivery_id, "
                "d.uidvalidity, d.uid, d.message_id, d.receive_status "
                "FROM attachment a JOIN delivery d ON d.id = a.delivery_id "
                "WHERE a.content_hash = ? ORDER BY d.id, a.id",
                (row["content_hash"],),
            ).fetchall()
            result["相同内容的投递"] = [dict(peer) for peer in peers]
        return result

    def content_source(self, content_hash: str) -> dict:
        self.store._validate(content_hash)
        rows = self.db.execute(
            "SELECT a.id AS attachment_id, a.part_path, a.original_filename, "
            "a.status, a.isolation_reason, d.id AS delivery_id, d.mailbox, "
            "d.uidvalidity, d.uid, d.message_id, d.receive_status, r.status AS ack_status "
            "FROM attachment a JOIN delivery d ON d.id = a.delivery_id "
            "LEFT JOIN receipt r ON r.delivery_id = d.id "
            "WHERE a.content_hash = ? ORDER BY d.id, a.id",
            (content_hash,),
        ).fetchall()
        content = self.db.execute(
            "SELECT * FROM content WHERE hash = ?", (content_hash,)
        ).fetchone()
        return {
            "内容摘要": content_hash,
            "大小": content["size"] if content else None,
            "存储路径": str(self.store.path_for(content_hash)),
            "文件存在": self.store.exists(
                content_hash, content["size"] if content else None
            ),
            "投递来源": [dict(row) for row in rows],
        }

    def isolated(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT a.id, a.delivery_id, a.part_path, a.original_filename, "
            "a.content_type, a.size, a.isolation_reason, a.isolation_detail, "
            "d.uidvalidity, d.uid, d.message_id, d.receive_status "
            "FROM attachment a JOIN delivery d ON d.id = a.delivery_id "
            "WHERE a.status = 'isolated' ORDER BY d.id, a.id"
        ).fetchall()
        return [dict(row) for row in rows]

    def status(self) -> dict:
        counts = {}
        for table in (
            "generation",
            "delivery",
            "attachment",
            "content",
            "receipt",
            "ledger_event",
        ):
            counts[table] = self.db.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
        delivery_states = {
            row["receive_status"]: row["n"]
            for row in self.db.execute(
                "SELECT receive_status, COUNT(*) AS n FROM delivery GROUP BY receive_status"
            )
        }
        receipt_states = {
            row["status"]: row["n"]
            for row in self.db.execute(
                "SELECT status, COUNT(*) AS n FROM receipt GROUP BY status"
            )
        }
        return {
            "行数": counts,
            "接收状态": delivery_states,
            "确认状态": receipt_states,
        }
