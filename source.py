from copy import deepcopy

class Mailbox:
    """本地邮箱适配器：不联网，可注入确认失败与身份重建。"""

    def __init__(self,fixture):
        self.generation=fixture['uidvalidity']
        self.messages={entry['uid']:entry['raw'].encode() for entry in fixture['messages']}
        self.flags=set()
        self.fail_ack=False
        self.ack_attempts=0

    def list_uids(self):
        return self.generation,sorted(self.messages)

    def fetch(self,uid):
        return self.messages[uid]

    def acknowledge(self,generation,uid):
        self.ack_attempts+=1
        if generation!=self.generation:
            raise ValueError('邮箱身份已变化')
        if uid not in self.messages:
            raise KeyError(uid)
        if self.fail_ack:
            raise ConnectionError('处理标记暂未确认')
        self.flags.add((generation,uid))

    def reset(self,messages):
        """模拟 UIDVALIDITY 重建；同一 UID 可以指向另一封信。"""
        self.generation+=1
        if isinstance(messages,dict):
            self.messages={int(uid):self._raw(raw) for uid,raw in messages.items()}
        else:
            self.messages={int(entry['uid']):self._raw(entry['raw']) for entry in messages}
        self.flags.clear()
        self.ack_attempts=0

    def redeliver(self, uid, raw):
        """转投/重投：UID 不变，原始字节可以不同。"""
        self.messages[int(uid)]=self._raw(raw)

    @staticmethod
    def _raw(raw):
        return raw.encode() if isinstance(raw,str) else raw
