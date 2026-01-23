# Do NOT mutate this at runtime from controllers.
BASE_RESOLVER = "{base}"  # placeholder; the controller will inject the real URL

methods = [
    {
        "method": "web",
        "pattern": "^(did:web:.+)$",
        "accept": ["application/did+json", "application/did-resolution+json"],
        "resolverEndpointTemplate": BASE_RESOLVER,
        "description": "W3C DID method 'web' resolved from hosted did.json",
    },
]
