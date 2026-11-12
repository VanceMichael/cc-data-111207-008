import json
import unittest
from pathlib import Path
from reader import inspect
from source import Mailbox


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads((Path(__file__).parents[1] / "fixtures/source.json").read_text(encoding="utf-8"))
        self.mailbox = Mailbox(self.fixture)

    def test_preview_attachment_name(self):
        from reader import preview
        self.assertEqual(preview(self.mailbox.fetch(11))['attachments'][0]['name'],'measure.csv')

    def test_ack_rejects_old_generation(self):
        self.mailbox.reset({11:b'Message-ID: <new@example.invalid>\n\n'})
        with self.assertRaises(ValueError):self.mailbox.acknowledge(7,11)

    def test_ack_failure_leaves_unmarked(self):
        self.mailbox.fail_ack=True
        with self.assertRaises(ConnectionError):self.mailbox.acknowledge(7,11)
        self.assertEqual(self.mailbox.flags,set())

    def test_base64_content(self):
        from email import policy
        from email.parser import BytesParser
        message=BytesParser(policy=policy.default).parsebytes(self.mailbox.fetch(11))
        part=list(message.iter_attachments())[0]
        self.assertEqual(part.get_payload(decode=True),b'id,value\nA,18\n')

    def test_forward_and_empty_part_are_real_mime(self):
        from email import policy
        from email.parser import BytesParser
        message=BytesParser(policy=policy.default).parsebytes(self.mailbox.fetch(12))
        parts=list(message.iter_attachments())
        self.assertEqual(parts[0].get_content_type(),'message/rfc822')
        self.assertEqual(parts[1].get_filename(),'空结果.bin')
        self.assertEqual(parts[1].get_payload(decode=True),b'')

    def test_inline_and_encoded_name_are_available(self):
        from email import policy
        from email.parser import BytesParser
        message=BytesParser(policy=policy.default).parsebytes(self.mailbox.fetch(13))
        parts=list(message.walk())
        self.assertTrue(any(part.get_content_disposition()=='inline' for part in parts))
        self.assertTrue(any(part.get_filename()=='修订测量.csv' for part in parts))


if __name__ == "__main__":
    unittest.main()
