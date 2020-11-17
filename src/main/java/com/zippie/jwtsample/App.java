/*
Copyright (c) 2020 Zippie Hong Kong Limited

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. 
*/

package com.zippie.jwtsample;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;
import org.jose4j.jwk.JsonWebKey;
import java.security.NoSuchAlgorithmException;
import static org.jose4j.jwk.JsonWebKey.OutputControlLevel.*;

public class App 
{
    public static void main( String[] args ) throws JoseException, NoSuchAlgorithmException
    {
        EllipticCurveJsonWebKey ecJwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);

        System.out.println("PRIVATE KEY (include in App/load into app): " + ecJwk.toJson(INCLUDE_PRIVATE));

        System.out.println("PUBLIC KEY (publish on website): " + ecJwk.toJson(PUBLIC_ONLY));

        EllipticCurveJsonWebKey jwk = (EllipticCurveJsonWebKey) JsonWebKey.Factory.newJwk(ecJwk.toJson(INCLUDE_PRIVATE));

        // This would be string version of JSON body
        String content = "this is the content that will be signed";

        // Create a new JsonWebSignature object for the signing
        JsonWebSignature signerJws = new JsonWebSignature();
    
        // The content is the payload of the JWS   -- this would be the body of the API response
        signerJws.setPayload(content);
    
        // Set the signature algorithm on the JWS
        signerJws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
    
        // The private key is used to sign
        signerJws.setKey(jwk.getPrivateKey());
    
        // Set the Key ID (kid) header because it's just the polite thing to do.
        signerJws.setKeyIdHeaderValue(jwk.getKeyId());
    
        // Set the "b64" header to false, which indicates that the payload is not encoded
        // when calculating the signature (per RFC 7797)
        signerJws.setHeader(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false); // signerJws.getHeaders().setObjectHeaderValue(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false); with versions before 0.7.0
    
        // RFC 7797 requires that the "b64" header be listed as critical
        signerJws.setCriticalHeaderNames(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD);
    
        // Produce the compact serialization with an empty/detached payload,
        // which is the encoded header + ".." + the encoded signature
        String detachedContentJws = signerJws.getDetachedContentCompactSerialization();
        System.out.println("// For HTTP header in response");
        System.out.println("x-jws-signature: " + detachedContentJws);

        /* verification part */
        EllipticCurveJsonWebKey publicJwk = (EllipticCurveJsonWebKey) JsonWebKey.Factory.newJwk(ecJwk.toJson(PUBLIC_ONLY));

        JsonWebSignature verifierJws = new JsonWebSignature();

        // Set the algorithm constraints based on what is agreed upon or expected from the sender
        verifierJws.setAlgorithmConstraints(new AlgorithmConstraints(
                AlgorithmConstraints.ConstraintType.PERMIT,
                AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256));
    
        // The JWS with detached content is the compact serialization
        verifierJws.setCompactSerialization(detachedContentJws);
    
        // The unencoded detached content is the payload
        verifierJws.setPayload(content);
    
        // The public key is used to verify the signature
        verifierJws.setKey(publicJwk.getPublicKey());
    
        // Check the signature
        boolean signatureVerified = verifierJws.verifySignature();
        
        // Do whatever needs to be done with the result of signature verification
        System.out.println("");
        System.out.println("JWS Signature is valid: " + signatureVerified);

   }
}
