package practice.jwt_test.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import practice.jwt_test.model.Member;
import practice.jwt_test.oauth.PrincipalDetails;
import practice.jwt_test.repository.MemberRepository;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private MemberRepository memberRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, MemberRepository memberRepository) {
        super(authenticationManager);
        this.memberRepository = memberRepository;
    }


   @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소 요청 됨.");

       String jwtHeader = request.getHeader("Authorization");

       if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
           chain.doFilter(request, response);
           return;
       }

       String jwtToken = jwtHeader.replace("Bearer ", "");

       // 토큰이 있더라도 verify() 메서드를 통해 username이 있는지 확인하여 우리 서비스에 등록된 유저인지 확인
       String username = JWT.require(Algorithm.HMAC512("cos_jwt_token")).build()
               .verify(jwtToken)
               .getClaim("username").asString();

       if(username != null) {
           Member memberEntity = memberRepository.findByUsername(username);

           PrincipalDetails principalDetails = new PrincipalDetails(memberEntity);
           Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
           SecurityContextHolder.getContext().setAuthentication(authentication);

           chain.doFilter(request,response);
       }
       super.doFilterInternal(request, response, chain);
    }
}
