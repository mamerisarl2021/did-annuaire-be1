package org.jwk;


public class Main {

    public static void main(String[] args)  {
        // Validate command-line arguments
        if(args.length != 1){
            System.err.println("Usage: java -jar ecdsa-extractor.jar <cert-path>");
            System.exit(1);
        }

        String certPath = args[0];

        try{
            String jwk = ECDSAJWKExtractor.extractJWK(certPath);
            System.out.println(jwk);
            System.exit(0);
        } catch (Exception e){
            System.err.println("Error extracting JWK: " + e.getMessage());
            System.exit(1);
        }
    }
}