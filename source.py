from copy import deepcopy

class Mailbox:
    def __init__(self,fixture):
        self.generation=fixture['uidvalidity']
        self.messages={entry['uid']:entry['raw'].encode() for entry in fixture['messages']}
        self.flags=set()
        self.fail_ack=False

    def list_uids(self):
        return self.generation,sorted(self.messages)

    def fetch(self,uid):
        return self.messages[uid]

    def acknowledge(self,generation,uid):
        if generation!=self.generation:
            raise ValueError('邮箱身份已变化')
        if uid not in self.messages:
            raise KeyError(uid)
        if self.fail_ack:
            raise ConnectionError('处理标记暂未确认')
        self.flags.add((generation,uid))

    def reset(self,messages):
        self.generation+=1
        self.messages=deepcopy(messages)
        self.flags.clear()
