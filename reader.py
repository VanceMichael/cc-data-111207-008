from email import policy
from email.parser import BytesParser
from mime_parse import parse_message

def preview(raw):
    message=BytesParser(policy=policy.default).parsebytes(raw)
    attachments=[]
    for part in message.iter_attachments():
        attachments.append({'name':part.get_filename(),'type':part.get_content_type()})
    return {'message_id':message.get('Message-ID'),'attachments':attachments}

def inspect(mailbox,fixture):
    generation,uids=mailbox.list_uids()
    return {'邮箱代次':generation,'邮件':[preview(mailbox.fetch(uid)) for uid in uids]}

def assess(raw,limits=None):
    """采集前预览：除附件名外，给出部件路径、隔离原因与整封状态。"""
    result=parse_message(raw,limits)
    return {
        'message_id':result.message_id,
        'status':result.status,
        'reason':result.reason,
        'attachments':[
            {
                'part_path':item.part_path,
                'name':item.original_filename,
                'type':item.content_type,
                'status':item.status,
                'size':item.size,
                'isolation_reason':item.isolation_reason,
            }
            for item in result.attachments
        ],
    }
