package hello.login.web.filter;

import hello.login.web.SessionConst;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.PatternMatchUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Slf4j
public class LoginCheckFilter implements Filter {

    private static final String[] whiteURIs = {"/", "/members/add", "/login", "/logout", "/css/*"};

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String requestURI = httpRequest.getRequestURI();

        try {
            log.info("인증 체크 필터 시작 {}", requestURI);

            if (isLoginCheckPath(requestURI)) {
                log.info("인증 체크 로직 실행 {}", requestURI);
                HttpSession session = httpRequest.getSession(false);

                if (session == null || session.getAttribute(SessionConst.LOGIN_MEMBER) == null) {
                    log.info("미인증 사용자 요청 {}", requestURI);

                    // 로그인으로 redirect + 뒤에 요청 URI를 같이 붙임.
                    httpResponse.sendRedirect("/login?redirectURL="+requestURI);
                    return; // 제일 중요. 리다이렉트 시키고 여기서 더 이상 다음으로 넘기지 않고 끝
                }
            }
            chain.doFilter(request, response);
        } catch (Exception e) {
            throw e; // 예외를 로깅가능하지만, 톰캣까지 예외를 보내주어야 함.
        } finally {
            log.info("인증 체크 필터 종료");
        }
    }


    /**
     * 화이트 리스트의 경우 인증체크 x
     */
    private boolean isLoginCheckPath(String requestURI) {
        return !PatternMatchUtils.simpleMatch(whiteURIs, requestURI);
    }
}
