package org.jwk;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import tools.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Base64;

public class ECDSAJWKExtractor {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String extractJWK(String certPath) throws Exception {
        // Load certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        try (InputStream is = Files.newInputStream(Paths.get(certPath))) {
            X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
            ECPublicKey publicKey = (ECPublicKey) cert.getPublicKey();

            return buildEcJwk(publicKey);
        }
    }

    private static String buildEcJwk(ECPublicKey publicKey) {
        // Extract point coordinates
        var x = publicKey.getW().getAffineX();
        var y = publicKey.getW().getAffineY();

        // Get curve name
        ECParameterSpec params = publicKey.getParams();
        String crv = getCurveName(params);

        // Construct JWK
        var jwk = new ObjectMapper().createObjectNode();
        jwk.put("kty", "EC");
        jwk.put("crv", crv);
        jwk.put("x", base64UrlEncode(x));
        jwk.put("y", base64UrlEncode(y));

        return jwk.toString();
    }

    private static String getCurveName(ECParameterSpec params) {
        // Check if it's a named curve
        if (params instanceof ECNamedCurveSpec namedSpec) {
            return mapCurveNameToJwk(namedSpec.getName());
        }

        // For explicit parameters, try to match against known curves
        try {
            org.bouncycastle.jce.spec.ECParameterSpec bcParams = convertToBCParams(params);
            return findMatchingCurve(bcParams);
        } catch (Exception e) {
            return "unknown";
        }
    }

    private static String findMatchingCurve(org.bouncycastle.jce.spec.ECParameterSpec params) {
        String[] commonCurves = {"secp256r1", "secp384r1", "secp521r1", "secp256k1"};

        for (String curveName : commonCurves) {
            X9ECParameters x9Params = ECNamedCurveTable.getByName(curveName);
            if (x9Params != null) {
                org.bouncycastle.jce.spec.ECParameterSpec knownParams =
                        new org.bouncycastle.jce.spec.ECParameterSpec(
                                x9Params.getCurve(),
                                x9Params.getG(),
                                x9Params.getN(),
                                x9Params.getH()
                        );

                if (areParamsEqual(params, knownParams)) {
                    return mapCurveNameToJwk(curveName);
                }
            }
        }

        return "unknown";
    }

    private static boolean areParamsEqual(
            org.bouncycastle.jce.spec.ECParameterSpec p1,
            org.bouncycastle.jce.spec.ECParameterSpec p2) {
        return p1.getCurve().equals(p2.getCurve()) &&
                p1.getG().equals(p2.getG()) &&
                p1.getN().equals(p2.getN());
    }

    private static org.bouncycastle.jce.spec.ECParameterSpec convertToBCParams(
            ECParameterSpec params) {

        org.bouncycastle.math.ec.ECCurve curve = convertCurve(params.getCurve());

        org.bouncycastle.math.ec.ECPoint g = curve.createPoint(
                params.getGenerator().getAffineX(),
                params.getGenerator().getAffineY()
        );

        return new org.bouncycastle.jce.spec.ECParameterSpec(
                curve,
                g,
                params.getOrder(),
                BigInteger.valueOf(params.getCofactor())
        );
    }

    private static org.bouncycastle.math.ec.ECCurve convertCurve(
            java.security.spec.EllipticCurve curve) {

        BigInteger p = ((java.security.spec.ECFieldFp) curve.getField()).getP();
        BigInteger a = curve.getA();
        BigInteger b = curve.getB();

        return new org.bouncycastle.math.ec.ECCurve.Fp(p, a, b, null, null);
    }

    private static String mapCurveNameToJwk(String bcName) {
        return switch (bcName.toLowerCase()) {
            case "secp256r1", "prime256v1", "p-256" -> "P-256";
            case "secp384r1", "p-384" -> "P-384";
            case "secp521r1", "p-521" -> "P-521";
            case "secp256k1" -> "secp256k1";
            default -> "unknown";
        };
    }

    private static String base64UrlEncode(BigInteger value) {
        byte[] bytes = value.toByteArray();

        // Remove leading zero byte if present (for positive numbers)
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            bytes = tmp;
        }

        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}