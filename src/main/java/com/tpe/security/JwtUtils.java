package com.tpe.security;

import com.tpe.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.util.Date;

/*
basic 3 metod yazacağız.
spring security nin anlıyacağı jwt classı oluşturuyoruz
    1-JWT generate(üretmek)
    2- JWT valide (kontrol)
    3-JWT Tokene userName ekleyen metod
 */
@Component
public class JwtUtils {         // bir nevi jwt alet cantamız diyebiliriz

    private String jwtSecret = "sboot";  // jwt generate yapmak için secret key lazım bu yuzden jwtSecret field ini oluşturduk

    private long jwtExpirationMs = 86400000; // jwt inin ömrünü belirliyoruz.  1 gün olarak ayarladık  24*60*60*1000

    /*
    jwt token oluşturulurken jwtSecret fieldi ile belirlediğimiz  jwtExpirationMs kullanacağız
     */

    // -------------- GENERATE TOKEN ---------------------------
    public String generateToken (Authentication authentication){            //bu aşamada kullanıcı doğrulama aşamasını geçmiştir.
        // bu yüzden   Authentication objesi çağrılır ve doğruanan kullanıcıya bunun üzerinden ulaşacağız
       UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal(); // getPrincipal() security e gider anlık olarak
                                                                                    // login işlemi yapan kullanıcıyı bize UserDetails olarak döndürür
        //bize lazım olan userName bilgisine UserDetails üzerinden ulaşacağız
       return Jwts. // jjwt bağımlılığını bu yuzden ekledik
                    builder().   // builder() içerisine gerekli parametreleri tanımlayınca jwt token üretir
                            setSubject(userDetails.getUsername()). // best practice UserName iledir. pasword dende üretebilirdik
                            setIssuedAt(new Date()).      // jwt tokenin ne zaman  üretildiğini bildiriyorum diyor ve setExpiration ile devam ediyoruz
                            setExpiration(new Date(new Date().getTime()+jwtExpirationMs)).   // (new Date().getTime()+jwtExpirationMs)--> ile anlık üretiln tarihin üzerine 1 gun eklemiş oluyoruz ve kullanım süresini belirliyoruz
                            signWith(SignatureAlgorithm.HS512,jwtSecret).  // jwt tokenimizin şifrelenme algoritmasını seçiyoruz
                            compact();  // verilenleri işle diyoruz
    }



    // -------------- VALİDATE TOKEN ---------------------------

    public boolean validateToken(String token){  // validate edilecek olması bize true ya da false döneceği anlamına geliyor

        try {
            Jwts.   //-> jjwt kutuphanesinden geliyor. generate etmek ya da validate etmek için kullanılır
                    parser()
                    .setSigningKey(jwtSecret) // şifrelenme tipini belirtiyoruz
                    .parseClaimsJws(token);
            // yani bu secret key ile birlikte bana gelen tokeni yeniden algoritmaya sokup  benim oluşturmuş olduğum token mi bilgisi alıyoruz
            return true ;
        } catch (ExpiredJwtException e) {
           e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }
        return false;
    }


    // -------------- JWT TOKEN den userName i alalım ---------------------------

    public String getUserNameFromJwtToken(String token){    // jwt tokenden userName getiren method
        return Jwts.parser().
                setSigningKey(jwtSecret).
                parseClaimsJws(token).  // algoritmaya tekrar sokma metodu
                getBody().  // tokeni oluştururken userName i "setSubject(userDetails.getUsername())." satırı ile body' sine setlemiştim
                getSubject(); // o yüzden burada önce getBody() ile çağırıp getSubject() ile username alabildim
    }




}
