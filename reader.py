from email import policy
from email.parser import BytesParser

def preview(raw):
    message=BytesParser(policy=policy.default).parsebytes(raw)
    attachments=[]
    for part in message.iter_attachments():
        attachments.append({'name':part.get_filename(),'type':part.get_content_type()})
    return {'message_id':message.get('Message-ID'),'attachments':attachments}

def inspect(mailbox,fixture):
    generation,uids=mailbox.list_uids()
    return {'邮箱代次':generation,'邮件':[preview(mailbox.fetch(uid)) for uid in uids]}
