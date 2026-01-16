from django.contrib import admin
from .models import DID, DIDDocument, Certificate, UploadedPublicKey, PublishRequest
admin.site.register(DID)
admin.site.register(DIDDocument)
admin.site.register(Certificate)
admin.site.register(UploadedPublicKey)
admin.site.register(PublishRequest)