"""把一封原始 MIME 邮件拆成可归档的附件与隔离项。

解析只负责读取和判定，不落盘。调用方拿到 ``AttachmentCandidate`` 后
再决定是否写入内容存储；隔离项即使没有内容字节，也会保留部件路径和
原因，便于事后查询，不会因为解析失败而假装整封邮件已经完整接收。
"""

from __future__ import annotations

import binascii
import hashlib
import io
import re
from dataclasses import dataclass, field
from email import policy
from email.generator import BytesGenerator
from email.parser import BytesParser
from typing import Iterable


# 这些缺陷说明部件结构或传输编码有问题。邮件头本身的瑕疵（例如发件人
# 写了一个不合规但可解码的显示名）不应让一个正常附件被隔离。
STRUCTURAL_DEFECTS = {
    "NoBoundaryInMultipartDefect",
    "StartBoundaryNotFoundDefect",
    "CloseBoundaryNotFoundDefect",
    "MultipartInvariantViolationDefect",
    "MissingHeaderBodySeparatorDefect",
    "InvalidMultipartContentTransferEncodingDefect",
}

DECODE_DEFECTS = {
    "InvalidBase64Defect",
    "InvalidBase64PaddingDefect",
    "InvalidBase64CharactersDefect",
    "InvalidBase64LengthDefect",
    "UndecodableBytesDefect",
}

ALLOWED_TRANSFER_ENCODINGS = {"", "7bit", "8bit", "binary", "base64", "quoted-printable"}

MAX_FILENAME_CHARS = 1024
MAX_HEADER_VALUE_CHARS = 4096


@dataclass(frozen=True)
class Limits:
    """单封邮件可消耗的资源上限。超过上限的内容进入隔离区。"""

    max_message_bytes: int = 16 * 1024 * 1024
    max_attachment_bytes: int = 8 * 1024 * 1024
    max_total_attachment_bytes: int = 32 * 1024 * 1024
    max_parts: int = 2000
    max_depth: int = 12


@dataclass
class AttachmentCandidate:
    part_path: str
    original_filename: str | None
    raw_content_disposition: str | None
    content_type: str
    disposition: str | None
    content_id: str | None
    content: bytes | None
    size: int | None
    status: str  # "ready" 或 "isolated"
    isolation_reason: str | None = None
    isolation_detail: str | None = None


@dataclass
class ParseResult:
    status: str  # complete / partial / rejected
    reason: str | None
    detail: str | None
    attachments: list[AttachmentCandidate] = field(default_factory=list)
    message_id: str | None = None
    subject: str | None = None
    sender: str | None = None
    message_fingerprint: str | None = None
    raw_size: int = 0
    defects: list[str] = field(default_factory=list)

    @property
    def stored_count(self) -> int:
        return sum(1 for item in self.attachments if item.status == "ready")

    @property
    def isolated_count(self) -> int:
        return sum(1 for item in self.attachments if item.status == "isolated")


def _text_header(message, name: str) -> str | None:
    value = message.get(name)
    if value is None:
        return None
    text = str(value).replace("\x00", "")
    if len(text) > MAX_HEADER_VALUE_CHARS:
        text = text[:MAX_HEADER_VALUE_CHARS]
    return text


def _filename(part) -> str | None:
    value = part.get_filename()
    if value is None:
        return None
    text = str(value).replace("\x00", "").replace("\r", "").replace("\n", "")
    if len(text) > MAX_FILENAME_CHARS:
        text = text[:MAX_FILENAME_CHARS]
    return text


def _defect_names(part) -> list[str]:
    return [type(defect).__name__ for defect in part.defects]


def _is_candidate(part) -> bool:
    if part.is_multipart():
        return False
    disposition = part.get_content_disposition()
    return bool(
        part.get_filename() is not None
        or disposition in {"attachment", "inline"}
        or part.get("Content-ID") is not None
    )


def _normalise_encoding(part) -> str:
    value = str(part.get("Content-Transfer-Encoding") or "")
    return value.strip().lower()


def _payload_length(part, encoding: str) -> int | None:
    """在完整解码前估算载荷大小，避免为大附件先分配内存。"""
    payload = part.get_payload(decode=False)
    if isinstance(payload, str):
        if encoding == "base64":
            return len(re.sub(r"\s+", "", payload)) * 3 // 4
        return len(payload)
    if isinstance(payload, bytes):
        return len(payload)
    return None


def _decode_payload(part, encoding: str) -> tuple[bytes | None, str | None, str | None]:
    """返回 (内容, 隔离原因, 说明)。"""

    if encoding in {"", "7bit", "8bit", "binary", "quoted-printable"}:
        payload = part.get_payload(decode=True)
        if payload is None:
            raw = part.get_payload(decode=False)
            if isinstance(raw, str):
                payload = raw.encode("utf-8", "surrogateescape")
            elif isinstance(raw, bytes):
                payload = raw
            else:
                return None, "decode_error", "无法取得部件内容"
        return payload, None, None

    if encoding == "base64":
        raw = part.get_payload(decode=False)
        if not isinstance(raw, str):
            return None, "decode_error", "base64 部件没有文本载荷"
        cleaned = re.sub(r"\s+", "", raw)
        if not cleaned:
            return b"", None, None
        try:
            # 标准库默认解码很宽松，会把 '!!!!' 解成空内容。对附件使用
            # strict_mode，让损坏的 base64 明确进入隔离区。
            return binascii.a2b_base64(cleaned, strict_mode=True), None, None
        except (binascii.Error, ValueError) as error:
            return None, "decode_error", f"base64 解码失败: {error}"

    return None, "unsupported_encoding", f"不支持的传输编码: {encoding}"


def _isolated(
    part,
    part_path: str,
    reason: str,
    detail: str | None,
    size: int | None = None,
) -> AttachmentCandidate:
    return AttachmentCandidate(
        part_path=part_path,
        original_filename=_filename(part),
        raw_content_disposition=_text_header(part, "Content-Disposition"),
        content_type=part.get_content_type(),
        disposition=part.get_content_disposition(),
        content_id=_text_header(part, "Content-ID"),
        content=None,
        size=size,
        status="isolated",
        isolation_reason=reason,
        isolation_detail=detail,
    )


class _Walker:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.part_count = 0
        self.total_bytes = 0
        self.attachments: list[AttachmentCandidate] = []
        self.defects: list[str] = []
        self.structure_problem: str | None = None
        self._stopped = False

    def note_structure(self, path: str, names: Iterable[str]) -> None:
        names = list(names)
        if not names:
            return
        self.defects.extend(f"{path or 'root'}:{name}" for name in names)
        if self.structure_problem is None and any(
            name in STRUCTURAL_DEFECTS for name in names
        ):
            self.structure_problem = f"{path or 'root'} 存在 MIME 结构缺陷: " + ", ".join(
                names
            )

    def visit(self, part, path: str, depth: int) -> None:
        if self._stopped:
            return
        self.part_count += 1
        if self.part_count > self.limits.max_parts:
            self.attachments.append(
                _isolated(part, path, "part_limit", f"超过最大部件数 {self.limits.max_parts}")
            )
            self._stopped = True
            return
        if depth > self.limits.max_depth:
            # 到达上限后不再继续解析内层，只留下一条可查询的隔离记录。
            self.attachments.append(
                _isolated(
                    part,
                    path,
                    "depth_exceeded",
                    f"超过最大嵌套深度 {self.limits.max_depth}",
                )
            )
            return

        defects = _defect_names(part)
        if part.is_multipart():
            self.note_structure(path, defects)
        else:
            structural = [name for name in defects if name in STRUCTURAL_DEFECTS]
            if structural:
                self.note_structure(path, structural)

        if part.get_content_type() == "message/rfc822":
            encoding = _normalise_encoding(part)
            if encoding == "base64":
                # 标准库把 message/* 的正文当内嵌邮件直接解析，不会先做
                # base64 解码，得到的结构不可信。宁可隔离并留痕，也不发布
                # 猜测出来的内容。
                self.attachments.append(
                    _isolated(
                        part,
                        path,
                        "unsupported_encoding",
                        "message/rfc822 使用 base64，无法可靠解析内嵌邮件",
                    )
                )
                return
            embedded = self._embedded_nodes(part)
            if not embedded:
                self.attachments.append(
                    _isolated(part, path, "decode_error", "message/rfc822 没有可解析的内嵌邮件")
                )
                return
            if _filename(part):
                # 转发邮件本身是带文件名的附件，发布序列化后的完整内嵌邮件；
                # 随后仍继续遍历它的部件，内层附件保留各自来源。
                self._publish_embedded(part, path, embedded[0])
            for index, inner in enumerate(embedded, start=1):
                self.visit(inner, f"{path}.{index}", depth + 1)
            return
            return
        if part.is_multipart():
            for index, child in enumerate(part.get_payload(), start=1):
                child_path = f"{path}.{index}" if path else str(index)
                self.visit(child, child_path, depth + 1)
            return

        if _is_candidate(part):
            self._collect_leaf(part, path, defects)

    @staticmethod
    def _embedded_nodes(part):
        payload = part.get_payload()
        if isinstance(payload, list) and payload:
            return payload
        if part.get_content_maintype() == "message":
            raw = part.get_payload(decode=True)
            if isinstance(raw, bytes) and raw:
                return [BytesParser(policy=policy.default).parsebytes(raw)]
        return []

    def _publish_embedded(self, part, path: str, inner) -> None:
        buffer = io.BytesIO()
        try:
            BytesGenerator(buffer, policy=policy.default).flatten(inner)
        except Exception as error:
            self.attachments.append(
                _isolated(part, path, "decode_error", f"转发邮件序列化失败: {error}")
            )
            return
        content = buffer.getvalue()
        if len(content) > self.limits.max_attachment_bytes:
            self.attachments.append(
                _isolated(
                    part,
                    path,
                    "too_large",
                    f"转发邮件 {len(content)} 字节，超过上限 {self.limits.max_attachment_bytes}",
                    size=len(content),
                )
            )
            return
        if self.total_bytes + len(content) > self.limits.max_total_attachment_bytes:
            self.attachments.append(
                _isolated(
                    part,
                    path,
                    "total_size_limit",
                    f"整封附件累计将超过上限 {self.limits.max_total_attachment_bytes}",
                    size=len(content),
                )
            )
            return
        self.total_bytes += len(content)
        self.attachments.append(
            AttachmentCandidate(
                part_path=path,
                original_filename=_filename(part),
                raw_content_disposition=_text_header(part, "Content-Disposition"),
                content_type=part.get_content_type(),
                disposition=part.get_content_disposition(),
                content_id=_text_header(part, "Content-ID"),
                content=content,
                size=len(content),
                status="ready",
            )
        )

    def _collect_leaf(self, part, path: str, defects: list[str]) -> None:
        encoding = _normalise_encoding(part)
        if encoding not in ALLOWED_TRANSFER_ENCODINGS:
            self.attachments.append(
                _isolated(part, path, "unsupported_encoding", f"不支持的传输编码: {encoding}")
            )
            return
        if any(name in DECODE_DEFECTS for name in defects):
            self.attachments.append(
                _isolated(part, path, "mime_defect", ", ".join(defects))
            )
            return

        estimated = _payload_length(part, encoding)
        if estimated is not None and estimated > self.limits.max_attachment_bytes:
            self.attachments.append(
                _isolated(
                    part,
                    path,
                    "too_large",
                    f"附件解码前约 {estimated} 字节，超过上限 {self.limits.max_attachment_bytes}",
                    size=estimated,
                )
            )
            return

        content, reason, detail = _decode_payload(part, encoding)
        if reason is not None:
            self.attachments.append(_isolated(part, path, reason, detail))
            return
        assert content is not None
        if len(content) > self.limits.max_attachment_bytes:
            self.attachments.append(
                _isolated(
                    part,
                    path,
                    "too_large",
                    f"附件 {len(content)} 字节，超过上限 {self.limits.max_attachment_bytes}",
                    size=len(content),
                )
            )
            return
        if self.total_bytes + len(content) > self.limits.max_total_attachment_bytes:
            self.attachments.append(
                _isolated(
                    part,
                    path,
                    "total_size_limit",
                    f"整封附件累计将超过上限 {self.limits.max_total_attachment_bytes}",
                    size=len(content),
                )
            )
            return

        self.total_bytes += len(content)
        self.attachments.append(
            AttachmentCandidate(
                part_path=path,
                original_filename=_filename(part),
                raw_content_disposition=_text_header(part, "Content-Disposition"),
                content_type=part.get_content_type(),
                disposition=part.get_content_disposition(),
                content_id=_text_header(part, "Content-ID"),
                content=content,
                size=len(content),
                status="ready",
            )
        )


def parse_message(raw: bytes, limits: Limits | None = None) -> ParseResult:
    """解析一封原始邮件；永不抛出解析异常，失败会变成 rejected 状态。"""

    limits = limits or Limits()
    fingerprint = hashlib.sha256(raw).hexdigest()
    if len(raw) > limits.max_message_bytes:
        return ParseResult(
            status="rejected",
            reason="message_too_large",
            detail=f"邮件 {len(raw)} 字节，超过上限 {limits.max_message_bytes}",
            message_fingerprint=fingerprint,
            raw_size=len(raw),
        )

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as error:  # 解析器本身也可能遇到病态输入
        return ParseResult(
            status="rejected",
            reason="parse_error",
            detail=f"{type(error).__name__}: {error}",
            message_fingerprint=fingerprint,
            raw_size=len(raw),
        )

    walker = _Walker(limits)
    try:
        walker.visit(message, "", 0)
    except Exception as error:
        return ParseResult(
            status="rejected",
            reason="parse_error",
            detail=f"{type(error).__name__}: {error}",
            message_fingerprint=fingerprint,
            raw_size=len(raw),
            message_id=_text_header(message, "Message-ID"),
            subject=_text_header(message, "Subject"),
            sender=_text_header(message, "From"),
        )

    if walker.structure_problem:
        reason, detail = "mime_structure", walker.structure_problem
        status = "partial"
    elif any(item.status == "isolated" for item in walker.attachments):
        reason, detail = "attachment_isolated", "至少一个附件未通过校验或被资源上限限制"
        status = "partial"
    else:
        reason, detail = None, None
        status = "complete"

    return ParseResult(
        status=status,
        reason=reason,
        detail=detail,
        attachments=walker.attachments,
        message_id=_text_header(message, "Message-ID"),
        subject=_text_header(message, "Subject"),
        sender=_text_header(message, "From"),
        message_fingerprint=fingerprint,
        raw_size=len(raw),
        defects=walker.defects,
    )
