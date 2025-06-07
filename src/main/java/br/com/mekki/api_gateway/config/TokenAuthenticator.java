package br.com.mekki.api_gateway.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class TokenAuthenticator {

    static final String SECRET = "MySecret";


    public static Claims validateToken(String token){

       try{
           JwtParser parser = Jwts.parser()
                   .setSigningKey(SECRET);

           return parser.parseClaimsJws(token).getBody();
       }catch (Exception e) {
           System.out.println("EXCEPTION in getAuthentication: " + e);
           return null;
       }
    }



}
