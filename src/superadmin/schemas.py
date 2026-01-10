from ninja import Schema


class RefusePayload(Schema):
    reason: str
