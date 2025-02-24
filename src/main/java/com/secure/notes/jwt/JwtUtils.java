package com.secure.notes.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String getJwtTokenFromHeader(HttpServletRequest request){
       String jwtTokenFromHeader = request.getHeader("Authorization");
       if(jwtTokenFromHeader!=null && jwtTokenFromHeader.startsWith("Bearer ")){
           return jwtTokenFromHeader.substring(7);
       }
       return null;
    }

    public String generateTokenFromUsername(UserDetails userDetails){
        String userName = userDetails.getUsername();
        return Jwts.builder()
                .subject(userName)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime()+jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    public String getUserNameFromJwtToken(String jwtToken){
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build().parseSignedClaims(jwtToken)
                .getPayload().getSubject();
    }
    private Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public boolean validateJwtToken(String jwtToken){
        try{
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(jwtToken);
            return true;
        }catch(MalformedJwtException e){
            System.out.println("Invalid JWT Token : "+e.getMessage());
        }catch(ExpiredJwtException e){
            System.out.println("Invalid JWT Token : "+e.getMessage());
        }catch(UnsupportedJwtException e){
            System.out.println("JWT Token is expired: "+e.getMessage());
        }catch(IllegalArgumentException e){
            System.out.println("JWT claims string is empty : "+e.getMessage());
        }
        return false;
    }


}
