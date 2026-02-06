from time import perf_counter
from urllib.parse import quote

from django.http import JsonResponse
from ninja_extra import api_controller, route
from ninja.errors import HttpError

from src.dids.did_registry_api.schemas.envelopes import err
from src.dids.resolver.services import load_from_fs, load_from_db, parse_did_web


def _wants_resolution(accept: str) -> bool:
    acc = (accept or "").lower()
    return "application/did-resolution+json" in acc


@api_controller("/universal-resolver", tags=["DID Resolver"], auth=None)
class ResolverController:
    @route.get("/identifiers/{identifier}")
    def resolve(self, request, identifier: str):
        accept = request.headers.get("Accept", "")
        t0 = perf_counter()
        try:
            d0 = perf_counter()
            try:
                doc = load_from_fs(identifier)
            except Exception:
                doc = load_from_db(identifier)
            driver_duration_ms = int((perf_counter() - d0) * 1000)
        except Exception:
            doc = None
            raise HttpError(404, "DID Document not found")

        if not isinstance(doc, dict):
            return err(
                request,
                404,
                "resolver_error: DID must resolve to a valid https URL containing a JSON document: Error: Bad response Forbidden",
                path=f"/api/universal-resolver/identifiers/{quote(identifier, safe=':')}",
            )

        total_ms = int((perf_counter() - t0) * 1000)

        if _wants_resolution(accept):
            # Parser block
            try:
                host, org, user, doc_type = parse_did_web(identifier)
                parser = {
                    "did": identifier,
                    "method": "web",
                    "method_id": f"{host}:{org}:{user}:{doc_type}",
                    "query": request.GET.get("c", "Not available"),
                }
            except Exception:
                parser = {
                    "did": identifier,
                    "method": "Not available",
                    "method_id": "Not available",
                    "query": request.GET.get("c", "Not available"),
                }

            # Services block
            services = doc.get("service")
            services_block = (
                [
                    {
                        "id": s.get("id"),
                        "type": s.get("type"),
                        "service_endpoint": s.get("serviceEndpoint"),
                    }
                    for s in services
                ]
                if isinstance(services, list) and services
                else "NOT AVAILABLE"
            )

            # Verification methods block
            vms = [
                {
                    "id": vm.get("id"),
                    "type": vm.get("type"),
                    "public_key_jwk": vm.get("publicKeyJwk"),
                }
                for vm in (doc.get("verificationMethod") or [])
            ]

            driver_url = request.build_absolute_uri(request.get_full_path())

            res = {
                "didDocument": doc,
                "didDocumentMetadata": {"contentType": "application/did+json"},
                "didResolutionMetadata": {
                    "contentType": "application/did-resolution+json",
                    "driverUrl": driver_url,
                    "driverDuration": driver_duration_ms,
                    "duration": total_ms,
                    "pattern": "^(did:web:.+)$",
                    "did": {"didString": identifier, "method": "web"},
                },
                "resolution_response": {
                    "parser": parser,
                    "services": services_block,
                    "verification_methods": vms,
                },
            }
            return JsonResponse(
                res, status=200, content_type="application/did-resolution+json"
            )

        # Fallback: plain DID Document
        return JsonResponse(doc, status=200, content_type="application/did+json")
