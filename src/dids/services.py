from django.db import transaction
from django.utils.text import slugify
from django.utils import timezone
from django.conf import settings
from pathlib import Path
import json

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
import base64

from src.auditaction.models import AuditAction
from src.dids.models import Application, DIDDocument, PublicKey
from src.users.models import User, UserRole
from src.auditaction.services import audit_action_create


@transaction.atomic
def application_create(
    *, organization, created_by: User, name: str, description: str = ""
) -> Application:
    """Créer une application"""

    slug = slugify(name)

    # Vérifier l'unicité
    if Application.objects.filter(organization=organization, slug=slug).exists():
        raise ValueError(f"Une application avec le slug '{slug}' existe déjà")

    app = Application.objects.create(
        organization=organization,
        created_by=created_by,
        name=name,
        slug=slug,
        description=description,
    )

    # Audit
    audit_action_create(
        user=created_by,
        action="APPLICATION_CREATED",
        details={
            "application_id": app.id,
            "name": name,
            "organization": organization.name,
        },
    )

    return app


@transaction.atomic
def did_document_create(
    *, application: Application, created_by: User, domain: str, certificate_file
) -> DIDDocument:
    """
    Créer automatiquement un DID Document W3C à partir des inputs

    Workflow:
    1. Parse le certificat
    2. Extrait la clé publique
    3. Génère le DID
    4. Génère le DID Document W3C
    5. Sauvegarde en DRAFT
    """

    org = application.organization
    user_slug = slugify(f"{created_by.first_name}-{created_by.last_name}")

    # Générer le DID
    did = f"did:web:annuairedid-fe.qcdigitalhub.com:{org.slug}:{user_slug}:{application.slug}"

    # Parser le certificat
    cert_data = certificate_file.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    public_key = cert.public_key()

    # Extraire la clé publique en PEM
    public_key_pem = public_key.public_key_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Déterminer le type de clé
    key_type = _determine_key_type(public_key)

    # Convertir en JWK
    public_key_jwk = _convert_to_jwk(public_key, key_type)

    # Générer le DID Document W3C
    key_id = "#key-1"
    verification_method = {
        "id": f"{did}{key_id}",
        "type": key_type,
        "controller": did,
        "publicKeyJwk": public_key_jwk,
    }

    document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [verification_method],
        "authentication": [f"{did}{key_id}"],
        "assertionMethod": [f"{did}{key_id}"],
        "keyAgreement": [],
        "capabilityInvocation": [],
        "capabilityDelegation": [],
        "service": [],
    }

    # Créer le DID Document
    did_doc = DIDDocument.objects.create(
        did=did,
        application=application,
        created_by=created_by,
        domain=domain,
        document=document,
        version=1,
        status="DRAFT",
    )

    # Sauvegarder la clé publique
    PublicKey.objects.create(
        did_document=did_doc,
        key_id=key_id,
        key_type=key_type,
        public_key_pem=public_key_pem,
        public_key_jwk=public_key_jwk,
        certificate_file=certificate_file,
        controller=did,
        purposes=["authentication", "assertionMethod"],
        is_active=True,
    )

    # Audit
    audit_action_create(
        user=created_by,
        action=AuditAction.DID_CREATED,
        details={"did": did, "application": application.name},
    )

    return did_doc


@transaction.atomic
def did_document_publish_draft(
    *, did_document: DIDDocument, published_by: User
) -> DIDDocument:
    """Publier le DID Document en pré-production (draft)"""

    if did_document.status != "DRAFT":
        raise ValueError(f"Cannot publish document with status {did_document.status}")

    did_document.status = "PREPROD"
    did_document.preprod_published_at = timezone.now()
    did_document.preprod_published_by = published_by
    did_document.save()

    # Écrire le fichier dans /draft/
    _write_did_document_to_filesystem(did_document, environment="draft")

    # Audit
    audit_action_create(
        user=published_by,
        action="DID_DOCUMENT_PUBLISHED_DRAFT",
        details={"did": did_document.did},
    )

    return did_document


@transaction.atomic
def did_document_validate(
    *, did_document: DIDDocument, validated_by: User
) -> DIDDocument:
    """Admin organisation valide le DID Document"""

    if did_document.status != "PREPROD":
        raise ValueError("Only PREPROD documents can be validated")

    if validated_by.role != UserRole.ORG_ADMIN:
        raise PermissionError("Only ORG_ADMIN can validate")

    did_document.validated_at = timezone.now()
    did_document.validated_by = validated_by
    did_document.save()

    # Audit
    audit_action_create(
        user=validated_by,
        action="DID_DOCUMENT_VALIDATED",
        details={"did": did_document.did},
    )

    return did_document


@transaction.atomic
def did_document_publish_production(
    *, did_document: DIDDocument, published_by: User
) -> DIDDocument:
    """Publier le DID Document en production"""

    if did_document.status != "PREPROD":
        raise ValueError("Document must be in PREPROD status")

    if not did_document.validated_at:
        raise ValueError("Document must be validated by ORG_ADMIN first")

    # Vérifier les permissions
    if not published_by.can_publish_prod and published_by.role != "ORG_ADMIN":
        raise PermissionError("User does not have production publication rights")

    # Publier
    did_document.status = "PUBLISHED"
    did_document.prod_published_at = timezone.now()
    did_document.prod_published_by = published_by
    did_document.save()

    # Écrire le fichier en production
    _write_did_document_to_filesystem(did_document, environment="public")

    # Audit
    audit_action_create(
        user=published_by,
        action="DID_DOCUMENT_PUBLISHED_PRODUCTION",
        details={"did": did_document.did},
    )

    return did_document


@transaction.atomic
def did_document_revoke(
    *, did_document: DIDDocument, revoked_by: User, reason: str
) -> DIDDocument:
    """Révoquer un DID Document"""

    did_document.status = "REVOKED"
    did_document.revoked_at = timezone.now()
    did_document.revoked_by = revoked_by
    did_document.revocation_reason = reason
    did_document.save()

    # Supprimer les fichiers
    _delete_did_document_from_filesystem(did_document)

    # Audit
    audit_action_create(
        user=revoked_by,
        action=AuditAction.DID_REVOKED,
        details={"did": did_document.did, "reason": reason},
    )

    return did_document


def _write_did_document_to_filesystem(did_document: DIDDocument, environment: str):
    """Écrire le DID Document sur le filesystem pour que Nginx le serve"""

    # Parse le DID: did:web:domain:org:user:app -> /org/user/app/did.json
    parts = did_document.did.split(":")
    path_parts = parts[3:]  # org, user, app

    # Construire le chemin
    base_dir = Path(getattr(settings, "DID_DOCUMENTS_ROOT", "/var/www/dids"))
    env_dir = "draft" if environment == "draft" else "public"
    file_path = base_dir / env_dir / "/".join(path_parts) / "did.json"

    # Créer les répertoires
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # Écrire le document
    with open(file_path, "w") as f:
        json.dump(did_document.document, f, indent=2)


def _delete_did_document_from_filesystem(did_document: DIDDocument):
    """Supprimer le DID Document du filesystem"""

    parts = did_document.did.split(":")
    path_parts = parts[3:]

    base_dir = Path(getattr(settings, "DID_DOCUMENTS_ROOT", "/var/www/dids"))

    for env_dir in ["draft", "public"]:
        file_path = base_dir / env_dir / "/".join(path_parts) / "did.json"
        if file_path.exists():
            file_path.unlink()


def _determine_key_type(public_key) -> str:
    """Déterminer le type de clé"""

    if isinstance(public_key, rsa.RSAPublicKey):
        return "JsonWebKey2020"
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519VerificationKey2020"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name
        if curve_name == "secp256k1":
            return "EcdsaSecp256k1VerificationKey2019"
        else:
            return "JsonWebKey2020"
    else:
        return "JsonWebKey2020"


def _convert_to_jwk(public_key, key_type: str) -> dict:
    """Convertir une clé publique en format JWK"""

    if isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        return {
            "kty": "RSA",
            "n": base64.urlsafe_b64encode(
                numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
            )
            .decode()
            .rstrip("="),
            "e": base64.urlsafe_b64encode(
                numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
            )
            .decode()
            .rstrip("="),
        }
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(raw_bytes).decode().rstrip("="),
        }
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        numbers = public_key.public_numbers()
        curve_name = public_key.curve.name

        return {
            "kty": "EC",
            "crv": _ec_curve_to_jwk_crv(curve_name),
            "x": base64.urlsafe_b64encode(numbers.x.to_bytes(32, "big"))
            .decode()
            .rstrip("="),
            "y": base64.urlsafe_b64encode(numbers.y.to_bytes(32, "big"))
            .decode()
            .rstrip("="),
        }
    else:
        raise ValueError(f"Unsupported key type: {type(public_key)}")


def _ec_curve_to_jwk_crv(curve_name: str) -> str:
    """Convertir nom de courbe vers JWK crv"""
    mapping = {
        "secp256k1": "secp256k1",
        "secp256r1": "P-256",
        "secp384r1": "P-384",
        "secp521r1": "P-521",
    }
    return mapping.get(curve_name, curve_name)
