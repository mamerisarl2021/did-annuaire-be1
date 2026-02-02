from __future__ import annotations

import base64

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1_modules import rfc5280, rfc3279, rfc5480
from ecdsa import curves as ecdsa_curves


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


def _match_specified_to_jose(p: int, a: int, b: int, gx: int, gy: int, n: int, h: int | None) -> tuple[str, str, str] | tuple[None, None, None]:
    """
    Compare explicit domain parameters to known JOSE curves (P-256/384/521).
    Returns (detected_curve_name, jose_crv, jose_alg) or (None, None, None) if unknown.
    """
    candidates = [
        ('secp256r1', ecdsa_curves.NIST256p, 'P-256', 'ES256'),
        ('secp384r1', ecdsa_curves.NIST384p, 'P-384', 'ES384'),
        ('secp521r1', ecdsa_curves.NIST521p, 'P-521', 'ES512'),
    ]
    for name, c, crv, alg in candidates:
        if (p == c.curve.p() and
            a % p == c.curve.a() % p and
            b % p == c.curve.b() % p and
            gx == c.generator.x() and
            gy == c.generator.y() and
            n == c.order and
            (h is None or h == 1)):
            return name, crv, alg
    return None, None, None


def extract_ec_jwk_from_cert_der(cert_der: bytes) -> tuple[dict, dict]:
    """
    Parse X.509 certificate DER with EC public key.
    - For namedCurve: produce JOSE crv if known.
    - For explicit (specified) parameters: reconstruct and map to JOSE curves if possible; else crv="unknown".
    Returns (jwk, compliance_meta).
    """
    cert_asn1, _ = der_decode(cert_der, asn1Spec=rfc5280.Certificate())
    spki = cert_asn1['tbsCertificate']['subjectPublicKeyInfo']
    algo_oid = str(spki['algorithm']['algorithm'])

    if algo_oid != str(rfc5480.id_ecPublicKey):
        raise ValueError("Not an EC public key (id-ecPublicKey)")

    params_any = spki['algorithm']['parameters']
    spk_bits = spki['subjectPublicKey']

    try:
        q_bytes = spk_bits.asOctets()
    except Exception:
        q_bytes = bytes(int(b) for b in spk_bits.asNumbers())

    if not q_bytes or q_bytes[0] != 0x04:
        raise ValueError("Unsupported EC point format (expecting uncompressed SEC1 0x04)")

    meta = {
        "ec_params_encoding": "unknown",
        "status": "OK",
        "reason": None,
        "detected_curve": None,
        "jose_crv": None,
    }

    named_oid = None
    p = a = b = gx = gy = n = h = None

    if params_any.isValue:
        ecpk_params, _ = der_decode(params_any.asBinary(), asn1Spec=rfc3279.EcpkParameters())
        # CHOICE: namedCurve | specifiedCurve
        if ecpk_params.getName() == 'namedCurve':
            meta["ec_params_encoding"] = "named"
            named_oid = str(ecpk_params['namedCurve'])
        elif ecpk_params.getName() == 'specifiedCurve':
            meta["ec_params_encoding"] = "explicit"
            specified = ecpk_params['specifiedCurve']
            field_id = specified['fieldID']
            p = int(field_id['parameters'])
            curve = specified['curve']
            a = int.from_bytes(bytes(curve['a']), 'big')
            b = int.from_bytes(bytes(curve['b']), 'big')
            base_octets = bytes(specified['base'])
            if not base_octets or base_octets[0] != 0x04:
                raise ValueError("Unsupported EC base point format (expecting uncompressed)")
            total = len(base_octets) - 1
            flen = total // 2
            gx = int.from_bytes(base_octets[1:1+flen], 'big')
            gy = int.from_bytes(base_octets[1+flen:1+2*flen], 'big')
            n = int(specified['order'])
            h = int(specified['cofactor']) if specified['cofactor'].isValue else None
        else:
            meta["ec_params_encoding"] = "unknown"

    # Split public point into x/y
    if p is not None:
        flen_q = (p.bit_length() + 7) // 8
        x_b = q_bytes[1:1+flen_q]
        y_b = q_bytes[1+flen_q:1+2*flen_q]
    else:
        # Fallback: derive from total length
        total_q = len(q_bytes) - 1
        flen_q = total_q // 2
        x_b = q_bytes[1:1+flen_q]
        y_b = q_bytes[1+flen_q:1+2*flen_q]

    crv = None
    alg = None

    # Named curve OID → JOSE crv
    if named_oid:
        OID_TO_JOSE = {
            '1.2.840.10045.3.1.7': ('P-256', 'ES256'),     # prime256v1 / secp256r1
            '1.3.132.0.34':        ('P-384', 'ES384'),     # secp384r1
            '1.3.132.0.35':        ('P-521', 'ES512'),     # secp521r1
        }
        crv, alg = OID_TO_JOSE.get(named_oid, (None, None))
        meta.update({"detected_curve": named_oid, "jose_crv": crv})
        meta["status"] = "OK" if crv else "NON_COMPLIANT"
        if not crv:
            meta["reason"] = "UNKNOWN_CURVE_NAMED"
    elif meta["ec_params_encoding"] == "explicit":
        detected_name, jose_crv, jose_alg = _match_specified_to_jose(p, a, b, gx, gy, n, h)
        if jose_crv:
            crv, alg = jose_crv, jose_alg
            meta.update({
                "detected_curve": detected_name,
                "jose_crv": jose_crv,
                "status": "WARN",
                "reason": "EXPLICIT_EC_PARAMS"
            })
        else:
            crv = "unknown"
            alg = None
            meta.update({
                "detected_curve": None,
                "jose_crv": None,
                "status": "NON_COMPLIANT",
                "reason": "UNKNOWN_CURVE_EXPLICIT_PARAMS"
            })
    else:
        raise ValueError("EC parameters missing or unsupported")

    jwk = {"kty": "EC", "crv": crv, "x": _b64u(x_b), "y": _b64u(y_b)}
    if alg:
        jwk["alg"] = alg
    return jwk, meta