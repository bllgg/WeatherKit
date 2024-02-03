package org.bllgg.weatherkit;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import javassist.NotFoundException;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


public class JwtTokenGenerator
{
    private static final String BEGIN_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_KEY = "-----END PRIVATE KEY-----";
    private String keyId;
    private String issuer;
    private String appId;
    private long expirationTime;

    public JwtTokenGenerator() {
    }

    public String createToken(String key) throws NotFoundException {
        try
        {
            Map<String,Object> claims = new HashMap<>();
            claims.put( "sub", appId);
            String privateKey = key.replace( BEGIN_KEY, "" )
                    .replace( END_KEY, "" )
                    .replaceAll( "\\s+", "" );
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec( Base64.getDecoder().decode( privateKey ) );
            KeyFactory keyFactory = KeyFactory.getInstance( "EC" );
            PrivateKey pk = keyFactory.generatePrivate( keySpec );

            return Jwts.builder()
                    .setClaims( claims )
                    .setHeaderParam( "kid", keyId)
                    .setHeaderParam( "id", issuer + "." + appId) // this is the ID of the program
                    .setHeaderParam( "alg", "ES256" )
                    .setExpiration( new Date( System.currentTimeMillis() + expirationTime) )
                    .setIssuedAt( new Date( System.currentTimeMillis() ) )
                    .setIssuer(issuer)
                    .signWith( pk, SignatureAlgorithm.ES256 )
                    .compact();
        }
        catch( Exception e )
        {
            throw new NotFoundException( "Token is not available" );
        }

    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public void setAppId(String appId) {
        this.appId = appId;
    }

    public void setExpirationTime(long expirationTime) {
        this.expirationTime = expirationTime;
    }
}
