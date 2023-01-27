package com.tpe.security;

import org.springframework.beans.factory.annotation.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.context.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.util.*;
import org.springframework.web.filter.*;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;

/*
JwtUtils classı ile oluşturmuş olduğumuz tokeni filtreleme işlemine dahil etmek için kendi filtremizi oluşturuyoruz ve
tokeni buraya cağırıyoruz
 */
public class AuthTokenFilter extends OncePerRequestFilter { // kendi filterimizi yazdığımız için extend işlemini yapmak zorundayız

    @Autowired
    private JwtUtils jwtUtils; // oluşturduğumuz tokeni çağırıyoruz

    @Autowired
    private UserDetailsService userDetailsService; // filtrelemeden sonra gideceği katman burası old için enjekte ettik

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String jwtToken = parseJwt(request); // parseJwt metodumuzu burada cagırdık ve tokenimizi jwtToken objemize atadık

        try {
            if(jwtToken!=null && jwtUtils.validateToken(jwtToken)){

                String userName  = jwtUtils.getUserNameFromJwtToken(jwtToken);  // userName uniq yapıda oldugundan ve security contexe atamak için burada username alıyoruz
                UserDetails userDetails = userDetailsService.loadUserByUsername(userName); // security UserDetails classını bildiği için atamamızı gercekleştiriyoruz

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken( // authentice edilmiş kullanıcınınoluşması için alacağı parametreleri ekliyoruz
                /* kullanıcının kendisi ---->*/  userDetails,
                                null, // bizi doğrudan ilgilendirmediği için null yapıp geçiyoruz
                                userDetails.getAuthorities());  // kullanıcı datalarını istiyoruz
                SecurityContextHolder.getContext().setAuthentication(authentication); //  oluşan kullanıcıyı security contexte gönderiyoruz

            }
        } catch (UsernameNotFoundException e) {
            e.printStackTrace();
        }

        filterChain.doFilter(request,response); // security filtre katmanına 3. olarak yaptığğımız bütün  işlemleri ekliyoruz. bunu yazmazsak yaptıgımız işlemlerin hiçbir anlamı olmaz


    }

    /*
            Bize gelen request içerisindeki tokeni ayrıştırıp getirmesi için bu metodu oluşturup
        doFilterInternal() metodu içerisinde çagırıp kullanacagız
     */
    private String parseJwt(HttpServletRequest request){
        String header =  request.getHeader("Authorization");
        if(StringUtils.hasText(header) &&            //(StringUtils.hasText(header) requestlerin fieldleri içerisine erişme ve istediğimiz kontrolleri
                header.startsWith("Bearer ")) {     // enpointlerde ekli tokenlerin başında standart olarak "Bearer" yazılıdır. o yüzden startwith ile onu alıp getiriyoruz
            return header.substring(7);
        }
        return null;

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {   // filtrelenmesini istemediğimiz endpointleri belirtmek için bu methodu override ediyor
                                                                                            // endpointleri belirtiyoruz
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        return antPathMatcher.match("/register", request.getServletPath()) ||
                antPathMatcher.match("/login" , request.getServletPath());
    }
}