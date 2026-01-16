"""
┌──────────────────────────────┐
│        DID Registry API      │
│  (Django – logique métier)   │
│                              │
│ - create DID                 │
│ - update DID Document        │
│ - deactivate DID             │
│ - validation / gouvernance   │
└──────────────┬───────────────┘
               │
┌──────────────▼───────────────┐
│   DID Document Compiler      │
│                              │
│ - build DID                  │
│ - build DID Document         │
│ - inject verificationMethod  │
│ - inject services            │
│ - normalize (JWK only)       │
└──────────────┬───────────────┘
               │
┌──────────────▼───────────────┐
│  Proof & Crypto Engine       │
│                              │
│ - parse certificates         │
│ - extract public keys        │
│ - JWK normalization          │
│ - sign DID Document          │
└──────────────┬───────────────┘
               │
┌──────────────▼───────────────┐
│ Central DID Hosting (Nginx)  │
│                              │
│ https://domain/.../did.json │
│                              │
│ ← SOURCE DE VÉRITÉ OPÉRATION │
└──────────────────────────────┘
"""