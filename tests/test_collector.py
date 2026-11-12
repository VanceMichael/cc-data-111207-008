"""MIME 解析与账本采集的测试。"""

import json
import tempfile
import unittest
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser
from pathlib import Path

from collector import Collector
from mime_parse import Limits, parse_message
from source import Mailbox


ROOT = Path(__file__).parents[1]


def load_fixture():
    return json.loads((ROOT / "fixtures" / "source.json").read_text(encoding="utf-8"))


def simple_message(body_payload: str, filename="measure.csv", cte="base64"):
    return (
        "Message-ID: <simple@example.invalid>\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/mixed; boundary="b"\n'
        "\n"
        "--b\n"
        "Content-Type: text/csv\n"
        f'Content-Disposition: attachment; filename="{filename}"\n'
        f"Content-Transfer-Encoding: {cte}\n"
        "\n"
        f"{body_payload}\n"
        "--b--\n"
    ).encode()


class MimeParseTests(unittest.TestCase):
    def setUp(self):
        self.fixture = load_fixture()

    def test_base64_attachment_has_content(self):
        raw = self.fixture["messages"][0]["raw"].encode()
        result = parse_message(raw)
        self.assertEqual(result.status, "complete")
        self.assertEqual(len(result.attachments), 1)
        attachment = result.attachments[0]
        self.assertEqual(attachment.content, b"id,value\nA,18\n")
        self.assertEqual(attachment.part_path, "2")
        self.assertEqual(attachment.original_filename, "measure.csv")

    def test_forwarded_rfc822_and_empty_attachment(self):
        raw = self.fixture["messages"][1]["raw"].encode()
        result = parse_message(raw)
        self.assertEqual(result.status, "complete")
        self.assertEqual([a.part_path for a in result.attachments], ["2.1.2", "3"])
        self.assertEqual(result.attachments[0].original_filename, "measure.csv")
        self.assertEqual(result.attachments[1].original_filename, "空结果.bin")
        self.assertEqual(result.attachments[1].content, b"")

    def test_inline_image_and_encoded_filename(self):
        raw = self.fixture["messages"][2]["raw"].encode()
        result = parse_message(raw)
        self.assertEqual(result.status, "complete")
        inline = result.attachments[0]
        self.assertIsNone(inline.original_filename)
        self.assertEqual(inline.disposition, "inline")
        self.assertEqual(inline.content, b"inline-pixel")
        self.assertEqual(result.attachments[1].original_filename, "修订测量.csv")
        self.assertEqual(result.attachments[1].content, b"id,value\nA,19\n")

    def test_corrupt_base64_is_isolated_not_silently_empty(self):
        raw = simple_message("!!!!")
        result = parse_message(raw)
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.attachments[0].status, "isolated")
        self.assertEqual(result.attachments[0].isolation_reason, "decode_error")

    def test_bad_padding_is_isolated(self):
        raw = simple_message("aGVsbG8")
        result = parse_message(raw)
        self.assertEqual(result.attachments[0].status, "isolated")
        self.assertEqual(result.attachments[0].isolation_reason, "decode_error")

    def test_unsupported_transfer_encoding_is_isolated(self):
        raw = simple_message("abc", cte="x-uuencode")
        result = parse_message(raw)
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.attachments[0].isolation_reason, "unsupported_encoding")

    def test_large_attachment_is_limited_without_decoding_whole_payload(self):
        limits = Limits(max_attachment_bytes=16)
        raw = simple_message("a" * 40, cte="7bit")
        result = parse_message(raw, limits)
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.attachments[0].isolation_reason, "too_large")
        self.assertIsNone(result.attachments[0].content)

    def test_deep_nesting_is_limited(self):
        raw = simple_message("aWQsdmFsdWUKQSwxOAo=")
        for level in range(30):
            boundary = f"outer{level}"
            raw = (
                "MIME-Version: 1.0\n"
                f'Content-Type: multipart/mixed; boundary="{boundary}"\n'
                "\n"
                f"--{boundary}\n"
                "Content-Type: message/rfc822\n"
                "\n"
            ).encode() + raw + f"\r\n--{boundary}--\n".encode()
        result = parse_message(raw, Limits(max_depth=3))
        self.assertEqual(result.status, "partial")
        isolated = [
            a for a in result.attachments if a.isolation_reason == "depth_exceeded"
        ]
        self.assertTrue(isolated)
        self.assertTrue(all(a.status == "isolated" for a in result.attachments))

    def test_part_limit_stops_walking(self):
        parts = []
        for index in range(5):
            parts.append(
                f"--b\nContent-Type: text/plain\n"
                f'Content-Disposition: attachment; filename="f{index}.txt"\n\nx\n'
            )
        raw = (
            'Message-ID: <many@example.invalid>\nMIME-Version: 1.0\n'
            'Content-Type: multipart/mixed; boundary="b"\n\n'
            + "".join(parts)
            + "--b--\n"
        ).encode()
        result = parse_message(raw, Limits(max_parts=3))
        self.assertEqual(result.status, "partial")
        self.assertTrue(any(a.isolation_reason == "part_limit" for a in result.attachments))

    def test_unknown_path_like_filename_is_kept_only_as_metadata(self):
        raw = simple_message("aWQsdmFsdWUKQSwxOAo=", filename="../../etc/passwd")
        result = parse_message(raw)
        self.assertEqual(result.attachments[0].original_filename, "../../etc/passwd")
        self.assertEqual(result.attachments[0].status, "ready")

    def test_structure_defect_marks_message_partial(self):
        raw = (
            b"Message-ID: <broken@example.invalid>\n"
            b"MIME-Version: 1.0\n"
            b'Content-Type: multipart/mixed; boundary="missing"\n'
            b"\n"
            b"no boundary here\n"
        )
        result = parse_message(raw)
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.reason, "mime_structure")
        self.assertIn("StartBoundaryNotFoundDefect", " ".join(result.defects))

    def test_oversized_message_is_rejected(self):
        result = parse_message(b"x" * 100, Limits(max_message_bytes=50))
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.reason, "message_too_large")


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = load_fixture()
        self.mailbox = Mailbox(self.fixture)
        self.temp = tempfile.TemporaryDirectory()
        self.state = Path(self.temp.name) / "state"

    def tearDown(self):
        self.temp.cleanup()

    def collector(self, **kwargs):
        return Collector(self.mailbox, self.state, **kwargs)

    def test_collect_stores_content_and_confirms(self):
        with self.collector() as collector:
            summary = collector.collect()
            self.assertEqual(summary.received, 3)
            self.assertEqual(summary.confirmed, 3)
            self.assertEqual(self.mailbox.flags, {(7, 11), (7, 12), (7, 13)})
            source = collector.attachment_source(1)
            self.assertEqual(source["投递"]["UID"], 11)
            self.assertEqual(source["附件"]["MIME 部件路径"], "2")

    def test_same_bytes_share_blob_but_keep_both_deliveries(self):
        with self.collector() as collector:
            collector.collect()
            rows = collector.db.execute(
                "SELECT content_hash, delivery_id, part_path FROM attachment "
                "ORDER BY id"
            ).fetchall()
            hashes = {}
            for row in rows:
                hashes.setdefault(row["content_hash"], set()).add(row["delivery_id"])
            shared = [value for value in hashes.values() if len(value) > 1]
            self.assertTrue(shared)
            # measure.csv 直接投递和转发内嵌各有一条来源记录。
            deliveries = collector.db.execute(
                "SELECT COUNT(DISTINCT delivery_id) FROM attachment "
                "WHERE content_hash = ?",
                (rows[0]["content_hash"],),
            ).fetchone()[0]
            self.assertEqual(deliveries, 2)

    def test_same_name_different_content_is_not_treated_as_overwrite(self):
        with self.collector() as collector:
            collector.collect()
            first = collector.db.execute(
                "SELECT content_hash FROM attachment WHERE original_filename = 'measure.csv' "
                "ORDER BY id LIMIT 1"
            ).fetchone()[0]
        replacement = self.fixture["messages"][0]["raw"].replace(
            "aWQsdmFsdWUKQSwxOAo=", "aWQsdmFsdWUKQSwyMQo="
        )
        self.mailbox.redeliver(11, replacement)
        with self.collector() as collector:
            summary = collector.collect()
            self.assertEqual(summary.superseded, 1)
            rows = collector.db.execute(
                "SELECT message_fingerprint, superseded_at FROM delivery WHERE uid = 11 "
                "ORDER BY id"
            ).fetchall()
            self.assertEqual(len(rows), 2)
            self.assertIsNotNone(rows[0]["superseded_at"])
            self.assertIsNone(rows[1]["superseded_at"])
            self.assertNotEqual(
                rows[0]["message_fingerprint"], rows[1]["message_fingerprint"]
            )
            old_content = collector.db.execute(
                "SELECT content_hash FROM attachment WHERE delivery_id = 1"
            ).fetchone()[0]
            self.assertTrue(collector.store.exists(old_content))

    def test_uidvalidity_reset_keeps_old_deliveries(self):
        with self.collector() as collector:
            collector.collect()
        self.mailbox.reset(
            {
                11: (
                    "Message-ID: <another@example.invalid>\n"
                    "MIME-Version: 1.0\n"
                    'Content-Type: multipart/mixed; boundary="b"\n\n'
                    "--b\nContent-Type: text/csv\n"
                    'Content-Disposition: attachment; filename="other.csv"\n'
                    "Content-Transfer-Encoding: base64\n\n"
                    "aWQsdmFsdWUKQiwyCg==\n"
                    "--b--\n"
                )
            }
        )
        with self.collector() as collector:
            summary = collector.collect()
            self.assertEqual(summary.uidvalidity, 8)
            self.assertEqual(summary.stale, 0)
            rows = collector.db.execute(
                "SELECT uidvalidity, uid, message_id FROM delivery ORDER BY id"
            ).fetchall()
            self.assertEqual(len(rows), 4)
            self.assertEqual(rows[0]["uidvalidity"], 7)
            self.assertEqual(rows[-1]["uidvalidity"], 8)
            # 旧 UID 11 的附件来源仍然可查，没有被世代 8 覆盖。
            old = collector.attachment_source(1)
            self.assertEqual(old["投递"]["邮箱世代"], 7)
            self.assertEqual(old["附件"]["原始文件名"], "measure.csv")

    def test_ack_failure_is_recovered_after_restart_without_duplicate_publish(self):
        self.mailbox.fail_ack = True
        with self.collector() as collector:
            summary = collector.collect()
            self.assertEqual(summary.confirm_failed, 3)
            self.assertEqual(self.mailbox.flags, set())
            published = collector.db.execute(
                "SELECT COUNT(*) FROM attachment WHERE status = 'stored'"
            ).fetchone()[0]
            self.assertEqual(published, 5)
        self.mailbox.fail_ack = False
        with self.collector() as collector:
            summary = collector.collect()
            self.assertEqual(summary.confirmed, 3)
            self.assertEqual(self.mailbox.flags, {(7, 11), (7, 12), (7, 13)})
            self.assertEqual(
                collector.db.execute("SELECT COUNT(*) FROM attachment").fetchone()[0],
                published,
            )

    def test_crash_before_ledger_commit_does_not_publish_half_a_delivery(self):
        triggered = []

        def fault(stage, context):
            if stage == "after_blob_write" and not triggered:
                triggered.append(context)
                raise RuntimeError("模拟崩溃")

        with self.assertRaises(RuntimeError):
            with self.collector(fault=fault) as collector:
                collector.collect()
        self.assertEqual(self.mailbox.flags, set())
        with self.collector() as collector:
            summary = collector.collect()
            self.assertEqual(summary.received, 3)
            self.assertEqual(summary.confirmed, 3)
            self.assertEqual(
                collector.db.execute("SELECT COUNT(*) FROM delivery").fetchone()[0], 3
            )

    def test_crash_before_ack_leaves_pending_and_confirms_once(self):
        triggered = []

        def fault(stage, context):
            if stage == "before_ack" and not triggered:
                triggered.append(context)
                raise RuntimeError("模拟崩溃")

        with self.assertRaises(RuntimeError):
            with self.collector(fault=fault) as collector:
                collector.collect()
        self.assertEqual(
            self.mailbox.flags,
            set(),
        )
        with self.collector() as collector:
            summary = collector.collect()
            self.assertEqual(summary.confirmed, 3)
            self.assertEqual(self.mailbox.flags, {(7, 11), (7, 12), (7, 13)})

    def test_crash_after_ack_is_reconciled_not_reconfirmed(self):
        triggered = []

        def fault(stage, context):
            if stage == "after_ack_before_receipt" and not triggered:
                triggered.append(context)
                raise RuntimeError("模拟确认后崩溃")

        with self.assertRaises(RuntimeError):
            with self.collector(fault=fault) as collector:
                collector.collect()
        # 远端已经有一个标记，本地账本尚未记录确认。
        self.assertEqual(self.mailbox.flags, {(7, 11)})
        with self.collector() as collector:
            summary = collector.collect()
            self.assertEqual(summary.confirmed, 2)
            attempts = {
                row["delivery_id"]: row["attempts"]
                for row in collector.db.execute(
                    "SELECT delivery_id, attempts FROM receipt"
                )
            }
            # UID 11 通过远端标记补记，没有再调用一次 acknowledge。
            self.assertEqual(attempts[1], 0)
            self.assertEqual(attempts[2], 1)
            self.assertEqual(attempts[3], 1)

    def test_pending_receipt_becomes_stale_after_uidvalidity_change(self):
        self.mailbox.fail_ack = True
        with self.collector() as collector:
            collector.collect()
        self.mailbox.fail_ack = False
        self.mailbox.reset({11: self.fixture["messages"][0]["raw"]})
        with self.collector() as collector:
            summary = collector.collect()
            self.assertEqual(summary.stale, 3)
            receipts = {
                row["delivery_id"]: row["status"]
                for row in collector.db.execute(
                    "SELECT delivery_id, status FROM receipt"
                )
            }
            self.assertEqual(receipts[1], "stale")
            self.assertEqual(receipts[2], "stale")
            self.assertEqual(receipts[3], "stale")
            # 旧世代不会再被写标记，新世代的 UID 11 正常确认。
            self.assertEqual(self.mailbox.flags, {(8, 11)})

    def test_missing_content_is_repaired_from_mailbox(self):
        with self.collector() as collector:
            collector.collect()
            digest = collector.db.execute(
                "SELECT content_hash FROM attachment LIMIT 1"
            ).fetchone()[0]
            collector.store.path_for(digest).unlink()
            self.assertFalse(collector.store.exists(digest))
        with self.collector() as collector:
            summary = collector.collect()
            self.assertEqual(summary.repaired, 1)
            self.assertTrue(collector.store.exists(digest))
            # 已确认的投递不会因为补写内容而再次调用远端标记。
            self.assertEqual(
                collector.db.execute(
                    "SELECT attempts FROM receipt WHERE delivery_id = 1"
                ).fetchone()[0],
                1,
            )

    def test_path_traversal_filename_never_escapes_store(self):
        fixture = {
            "uidvalidity": 1,
            "messages": [
                {
                    "uid": 1,
                    "raw": simple_message(
                        "aWQsdmFsdWUKQSwxOAo=", filename="../../../tmp/evil.csv"
                    ).decode(),
                }
            ],
        }
        mailbox = Mailbox(fixture)
        with Collector(mailbox, self.state) as collector:
            collector.collect()
            row = collector.db.execute(
                "SELECT content_hash, original_filename FROM attachment"
            ).fetchone()
            self.assertEqual(row["original_filename"], "../../../tmp/evil.csv")
            path = collector.store.path_for(row["content_hash"])
            self.assertEqual(path.parent, self.state / "content")
            self.assertEqual(len(path.name), 64)

    def test_partial_message_is_not_acknowledged_and_keeps_other_attachments(self):
        raw = (
            "Message-ID: <partial@example.invalid>\n"
            "MIME-Version: 1.0\n"
            'Content-Type: multipart/mixed; boundary="b"\n'
            "\n"
            "--b\n"
            "Content-Type: text/csv\n"
            'Content-Disposition: attachment; filename="good.csv"\n'
            "Content-Transfer-Encoding: base64\n"
            "\n"
            "aWQsdmFsdWUKQSwxOAo=\n"
            "--b\n"
            "Content-Type: text/csv\n"
            'Content-Disposition: attachment; filename="bad.csv"\n'
            "Content-Transfer-Encoding: base64\n"
            "\n"
            "!!!!\n"
            "--b--\n"
        ).encode()
        fixture = {"uidvalidity": 1, "messages": [{"uid": 1, "raw": raw.decode()}]}
        mailbox = Mailbox(fixture)
        with Collector(mailbox, self.state) as collector:
            summary = collector.collect()
            self.assertEqual(summary.partial, 1)
            self.assertEqual(mailbox.flags, set())
            rows = collector.db.execute(
                "SELECT original_filename, status FROM attachment ORDER BY id"
            ).fetchall()
            self.assertEqual([(r["original_filename"], r["status"]) for r in rows],
                             [("good.csv", "stored"), ("bad.csv", "isolated")])
            delivery = collector.delivery_source(1)
            self.assertEqual(delivery["接收状态"], "partial")
            self.assertEqual(delivery["远端确认"]["状态"], "blocked")
            self.assertEqual(
                collector.isolated()[0]["isolation_reason"], "decode_error"
            )

    def test_preview_still_works(self):
        from reader import preview

        self.assertEqual(
            preview(self.mailbox.fetch(11))["attachments"][0]["name"], "measure.csv"
        )


if __name__ == "__main__":
    unittest.main()
