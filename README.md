
## java-spring-login

- 인프런 김영한님의 '스프링 MVC 2편 - 백엔드 웹개발 활용 기술' 강의
- 로그인 구현 학습을 위한 Repository

---

# 로그인/로그아웃 - 쿠키 기반

### 쿠키 기반 로그인
```java
@PostMapping("/login")
public String login(
        @Valid @ModelAttribute LoginForm form,
        BindingResult bindingResult,
        HttpServletResponse response) {

    if (bindingResult.hasErrors()) {
        return "login/loginForm";
    }

    Member loginMember = loginService.login(form.getLoginId(), form.getPassword());

    if (loginMember == null) {
        bindingResult.reject("LoginFail", "아이디 또는 패스워드가 맞지 않습니다.");
        return "login/loginForm";
    }

    //TODO : 로그인 성공처리

    // 쿠키에 시간 정보를 주지 않으면 세션 쿠키(브라우저 종료 시 모두 종료)
    Cookie idCookie = new Cookie("memberId", String.valueOf(loginMember.getId()));
    response.addCookie(idCookie);
    return "redirect:/";
}
```
```java
@PostMapping("/logout")
public String logOut(HttpServletResponse response) {
    expireCookie(response, "memberId");
    return "redirect:/";
}
```
- 로그인 성공 시 response에 id값을 value로 한 Cookie를 담아서, 응답
- 로그아웃 시 response에 만료쿠키를 담아서 응답


### 로그인에 따라 다른 페이지 보이기
```java
@GetMapping("/")
public String loginHome(
        @CookieValue(name="memberId", required = false) Long memberId,
        Model model) {
    if (memberId == null) {
        return "home";
    }

    // 로그인
    Member loginMember = memberRepository.findById(memberId);

    if (loginMember == null) {
        return "home";
    }
    model.addAttribute("member", loginMember);
    return "loginHome";
}
```
- `@CookieValue` : 쿠키의 id를 읽고 값을 바인딩
- 요청에 회원Id 쿠키값이 없으면 기본 홈 
- 일치하는 회원Id가 없으면 기본 홈
- 일치하는 회원Id가 존재하면 로그인 페이지 반환

---

## 쿠키의 보안문제

### 문제점
- 쿠키값은 클라이언트 측에서 임의로 변경/변조 가능
- 쿠키값은 훔쳐갈 수 있음.
- 해커가 쿠기값을 평생 사용할 수 있음.

### 대안?
- 중요한 값을 노출하지 않고, 사용자 별로 예측 불가능한 토큰값을 노출
- 토큰은 해커가 임의의 값을 넣어도 찾을 수 없도록 예상 불가능하게 해야함
- 서버에서 해당 토큰의 만료시간을 짧게(30분)유지. 또는 해킹 의심되는 경우 서버에서 해당 토큰을 강제로 제거
- 이런식으로 중요한 정보는 서버에서 보관하고, 연결을 유지하는 방법이 '세션'이다.

---

## 세션
- 중요한 정보는 모두 서버에 저장(key : sessionId, Value : 중요 데이터)
  - sessionId : 추정 불가능한 임의의 식별자값 (보통 UUID)
- 클라이언트-서버는 결국 '쿠키'로 연결되어 있음.

### 쿠키의 전달
1. 서버 : sessionId를 쿠키에 담아 응답
2. 클라이언트 : 서버로부터 받은 쿠키를 보관, 요청마다 쿠키를 같이 전달
3. 서버 : 이후 클라이언트가 보낸 쿠키의 sessionId 정보를 기반으로 세션 저장소를 조회해서 로그인 시 보관한 세션정보 사용

### 보안문제의 해결
- 세션을 사용해서 서버에서 중요한 정보를 관리하게 됨
- 쿠키값을 변조 가능하지만, 예상 불가능한 복잡한 세션 Id를 사용하기에 위험성이 줄어듬
  - sessionId가 털려도 중요한 정보는 서버측에서 관리함
  - sessionId를 탈취하여 사용해도, 일정 시간이 지나면 해당 sessionId를 사용할 수 없도록 만료 시간을 짧게 유지(보통 30분). 해킹 의심이 될 경우 서버에서 해당 세션을 강제로 제거하면 됨.

---

## 세션 구현하기

- 세션 생성 : sessionId 및 쿠키 생성
- 세션 조회 : 요청의 sessionId 쿠키값을 읽고 세션 저장소에 보관한 데이터 조회
- 세션 만료 : 요청의 sessionId 쿠키값을 읽고, 세션 저장소에 보관한 sessionId 제거

---

## V2 : 직접 만든 세션을 적용하여 로그인

### 로그인
```java
@PostMapping("/login")
public String loginV2(
@Valid @ModelAttribute LoginForm form,
        BindingResult bindingResult,
        HttpServletResponse response) {
        
        // 아이디, 패스워드 검증 및 멤버객체 반환과정 생략

        // TODO : 로그인 성공처리
        // 세션 관리자를 통해 세션을 생성하고, 회원 데이터 보관
        sessionManager.createSession(loginMember, response);
        return "redirect:/";
        }
```
- sessionManager를 통해 세션 생성(서버에서 사용자 데이터를 유지)
  - sessionId를 key, 사용자 정보를 value로 보관
  - response에 sessionId 값을 쿠키를 담음

### 로그아웃
```java
    @PostMapping("/logout")
    public String logOutV2(HttpServletRequest request) {
        sessionManager.expire(request);
        return "redirect:/";
    }
```
- 세션매니저에서 더이상 사용자 객체를 저장하지 않게 함.

### 홈 로그인
```java
    @GetMapping("/")
    public String loginHomeV2(HttpServletRequest request, Model model) {

        // 세션 관리자에 저장된 회원 정보 조회
        Member member = (Member) sessionManager.getSession(request);

        // 로그인
        if (member == null) {
            return "home";
        }

        model.addAttribute("member", member);
        return "loginHome";
    }
```
- 로그인 유저는 loginHome, 로그인 하지 않은 유저는 home을 보이도록 함.

---

## 서블릿 - HttpSession

### 로그인
```java
 @PostMapping("/login")
    public String loginV3(
            @Valid @ModelAttribute LoginForm form,
            BindingResult bindingResult,ㅏ
            HttpServletRequest request) {

        // 생략
        // 세션이 있으면 있는 세션 반환(재사용), 없으면 신규 세션을 생성
        HttpSession session = request.getSession();
        
        // 세션에 로그인 회원 정보 보관
        session.setAttribute(SessionConst.LOGIN_MEMBER, loginMember);
        return "redirect:/";
    }
```

### 세션의 생성과 조회
- request.getSession(...) : 기본이 true
  - request.getSession(true) : 세션이 있으면 있는 세션 반환(재사용), 없으면 새로 세션을 생성
  - request.getSession(false) : 세션이 있으면 있는 세션 반환(재사용), 없으면 null 반환

### 세션에 로그인 회원 정보 보관
- session.setAttribute(세션명, 보관하는 정보)
  - 하나의 세션에 여러개의 값을 저장할 수 있다.

### 로그아웃
```java
@PostMapping("/logout")
public String logOutV3(HttpServletRequest request) {
    HttpSession session = request.getSession(false); // 없으면 null 반환.
    
    if (session != null) {
        session.invalidate(); // 세션의 데이터 사라짐
    }
    return "redirect:/";
}
```
- session.invalidate() : 세션 제거

### homeLogin
```java
@GetMapping("/")
public String loginHomeV3(HttpServletRequest request, Model model) {

    HttpSession session = request.getSession(false);

    if (session == null) {
        return "home";
    }

    Member member = (Member) session.getAttribute(SessionConst.LOGIN_MEMBER);

    // 세션에 홈 데이터가 없으면 home
    if (member == null) {
        return "home";
    }

    // 세션이 유지되고 데이터가 있는 것이 확인되면 로그인 홈으로 이동
    model.addAttribute("member", member);
    return "loginHome";
}
```
- session.getAttribute(...) : 세션명에 대응하는 보관 데이터를 Object로 반환

### 스프링(`@SessionAttribute`)

```java
    @GetMapping("/")
    public String loginHomeV3Spring(
            @SessionAttribute(name = SessionConst.LOGIN_MEMBER, required = false) Member loginMember, Model model) {
        // 세션에 홈 데이터가 없으면 home
        if (loginMember == null) {
            return "home";
        }

        // 세션이 유지되고 데이터가 있는 것이 확인되면 로그인 홈으로 이동
        model.addAttribute("member", loginMember);
        return "loginHome";
    }
```
- 세션이 필요한 로직이 있을 때, `@SessionAttribute`를 통해 바로 객체 반환
  - name : 세션명
  - required : 필수값이면 true, 아니면 false

### URL에 세션값 넘기지 않기
```java
## URL에 세션값이 노출되지 않음
server.servlet.session.tracking-modes=cookie
```
- 웹브라우저가 쿠키를 지원하지 않을 때 쿠키 대신 URL을 통해 세션을 유지
- 서버 입장에선 브라우저가 지원하는지 안 하는지 여부를 모르므로, 쿠키 값도 URL에 전달함
- 이 방식을 끄려면 application.properties에서 별도로 설정해야함

---

## Session의 여러가지 메서드

```java
session.getAttributeNames().asIterator()
.forEachRemaining(name ->
log.info("session name = {}, value = {}", name, session.getAttribute(name)));

log.info("sessionId = {}", session.getId());
log.info("getMaxInactiveInterval = {}", session.getMaxInactiveInterval());
log.info("creationTime = {}", new Date(session.getCreationTime()));
log.info("lastAccessedTime = {}", new Date(session.getLastAccessedTime()));
log.info("isNew= {}",session.isNew());
return "세션 출력";
```
- `getAttributeNames()` : 각 (sessionName, Value)들에 접근
- `getMaxInactiveInterval()` : 세션의 유효시간. 1800(30분)초.
- `getCreationTime()` : 세션의 생성시각
- `getLastAccessedTime()` : 세션과 연결된 사용자가 최근에 서버에 접근한 시간.
- `isNew()` : 새로 생성되면 true, 아니면 false

---

## Session 타임아웃 설정

- 세션은 기본적으로 사용자가 로그아웃 요청시 `session.invalidate()`를 호출하여 사라짐
- 하지만 사용자가 단순히 창을 닫을 경우에는 서버 입장에선 사용자가 웹브라우저를 종료했는지 모름
- 계속해서 세션을 보관한다면 서버에 세션이 계속 남아있게 되고, 무한정 보관했다가는 다음 문제가 발생함
  - 세션과 관련된 쿠키를 탈취했을 때 보안상 위험
  - 세션은 메모리에 생성되는데 무한정 메모리를 차지하게 됨.

### 세션의 종료 시점
- 사용자가 최근 요청한 시점을 기준으로 특정 시간만큼 유지. 기본적으로 30분 유지함
  - LastAccessedTime 이후로 timeout 시간이 지나면, WAS가 내부에서 세션을 제거


### 글로벌 타임아웃 설정
```properties
## 세션 종료 시간 : lastAccessedTime 이후(초단위, 기본값 1800)
server.servlet.session.timeout=60
```
- `application.properties`에서 설정.
- 초 단위. 기본은 1800으로 잡혀있음.

### 특정 세션 단위로 시간 설정
```java
  session.setMaxInactiveInterval(1800); // 1800초
```

### 결론
- HttpSession의 타임아웃 기능 덕분에 편리하게 세션의 타임아웃을 관리할 수 있음
- 하지만 아무리 이렇게 HttpSession이 관리해주더라도, 세션에는 최소한의 데이터를 보관해야함.
  - 메모리 차지 용량 : 보관 데이터 용량 * 사용자 수 -> 장애 발생 가능성 증가
  - 필요에 따라 타임아웃 시간을 조정할 것. 기본값은 1800초

---

# 로그인 처리 2 - 필터, 인터셉터

## 7.1 서블릿 필터 - 소개
<details>
<summary>접기/펼치기 버튼</summary>
<div markdown="1">

### 7.1.1) 웹과 관련된 공통 관심사
- 공통관심사(cross-cutting-concern) : 애플리케이션 여러 로직에서 공통으로 관심이 있는 것
  - 일반적인 처리방법 : 스프링 AOP
- 웹과 관련된 공통관심사 처리 : 서블릿 필터, 스프링 인터셉터
  - http 헤더, url 등의 정보가 필요함.
  - 서블릿 필터, 스프링 인터셉터는 `HttpServletRequest`를 제공

### 7.1.2) 서블릿 필터의 흐름
```
HTTP 요청 -> WAS -> 필터 -> 서블릿 -> 컨트롤러
```
- 필터를 적용하면, 서블릿이 호출되기 전에 필터가 호출
  - 스프링에서는 디스패처 서블릿
- 필터는 글로벌하게 적용할 수도 있고, 특정 URL 패턴에 적용할 수 있음.
  - 예) `/*`로 하면 모든 요청에 필터가 적용됨

### 7.1.3) 서블릿 필터의 제한 처리
```
// 로그인 사용자
HTTP 요청 -> WAS -> 필터 -> 서블릿 -> 컨트롤러 
```
```
// 비 로그인 사용자
HTTP 요청 -> WAS -> 필터(적절하지 않은 요청이라 판단, 서블릿 호출 x) 
```
- 필터에서 적절하지 않은 요청이라 판단되면 거기서 끝을 낼 수 있음.
  - 로그인 여부 체크에 매우 유용하다.

### 7.1.4) 서블릿 필터 체인
```
HTTP 요청 -> WAS -> 필터1 -> 필터2 -> 필터3 -> ... -> 서블릿 -> 컨트롤러
```
- 필터는 체인으로 구성되고, 중간에 여러 필터를 자유롭게 추가할 수 있음.
  - 예) 로그필터 - 로그인 여부 체크 필터 - ...

### 7.1.5) Filter 인터페이스
```java
public interface Filter {

    public default void init(FilterConfig filterConfig) throws ServletException {}
  
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException;

    public default void destroy() {}
}
```
필터 인터페이스를 구현한 구현체를 등록하면 서블릿 컨테이너가 필터를 싱글톤 객체로 생성하고 관리
- `init()` : 필터 초기화 메서드
- `doFilter()` : 고객의 요청이 들어올 때마다 호출되는 메서드. 필터의 로직을 구현하면 됨
- `destoy()` : 필터 종료 메서드. 서블릿 컨테이너가 종료될 때 호출

</div>
</details>

## 7.2 서블릿 필터 - 요청 로그
<details>
<summary>접기/펼치기 버튼</summary>
<div markdown="1">

### LogFilter
```java
@Slf4j
public class LogFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        log.info("log filter init");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("log filter doFilter");

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        String uuid = UUID.randomUUID().toString();
        String requestURI = httpRequest.getRequestURI();

        try {
            log.info("REQUEST [{}][{}]",uuid, requestURI);
            chain.doFilter(request, response);
        } catch (Exception e) {
            throw e;
        } finally {
            log.info("RESPONSE [{}] [{}]", uuid, requestURI);
        }
    }
    
  // ... 생략
```
- implements Filter (import javax.servlet.*)
  - 필터를 사용하려면 Filter 인터페이스를 구현해야한다.
- doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
  - http 요청이 오면 호출됨
  - HTTP를 사용한다면 ServletRequest, ServletResponse를 HttpServletRequest, HttpServletResponse로 다운캐스팅해야함.
  - **chain.doFilter**
    - 다음 필터가 있으면 다음 필터 호출, 없으면 서블릿 호출
    - 이 로직이 호출되지 않으면 다음단계로 진행되지 않음
- String uuid
  - HTTP 요청을 구분하기 위함
- log.info(...)
  - uuid, requestURI 등을 출력

### WebConfig : 필터 설정
```java
@Configuration
public class WebConfig {

    @Bean
    public FilterRegistrationBean logFilter() {
        FilterRegistrationBean<Filter> filterRegistrationBean = new FilterRegistrationBean<>();
        filterRegistrationBean.setFilter(new LogFilter());
        filterRegistrationBean.setOrder(1);
        filterRegistrationBean.addUrlPatterns("/*");
        return filterRegistrationBean;
    }
}
```
- 스프링 부트 사용시 FilterRegistrationBean을 등록
  - setFilter : 필터 등록
  - serOrder : 순서 지정
  - addUrlPattern : 필터를 적용할 URL 패턴(한번에 여러 패턴 적용 가능)
    - url 패턴
      - 서블릿 URL패턴과 동일
- `@ServletComponentScan`, `@WebFilter(filterName="logFilter", urlPatterns="/*"`로 필터등록 가능
  - 하지만, 필터 순서 조절이 안 되므로 FilterRegistrationBean을 사용하는 것이 좋음
- 실무에서 HTTP 요청 시 같은 요청의 로그에 모두 같은 식별자를 자동으로 남기려면 logback.mdc로 검색

</div>
</details>

## 7.3 서블릿 필터 - 인증 체크
<details>
<summary>접기/펼치기 버튼</summary>
<div markdown="1">

### LoginCheckFilter
```java
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
```
- whiteURIs : 필터의 적용을 받지 않는 화이트리스트 목록
  - 인증필터를 적용하더라도 접근할 수 있어야하는 uri들
    - 예) 홈 화면, 회원가입 페이지, 로그인 화면, css 등
- `isLoginCheckPath`
  - 화이트 리스트가 아닌 일반 uri들인지 확인
- `sendRedirect` : 필터링 될 경우, "/login"으로 쿼리 파라미터에 함께 이전 url을 전달
- return : 더는 진행시키지 않음. redirect 시키고 요청 종료

### LoginCheckFilter 빈 등록
```java
@Bean
public FilterRegistrationBean loginCheckFilter() {
    FilterRegistrationBean<Filter> filterRegistrationBean = new FilterRegistrationBean<>();
    filterRegistrationBean.setFilter(new LoginCheckFilter());
    filterRegistrationBean.setOrder(2);
    filterRegistrationBean.addUrlPatterns("/*");
    return filterRegistrationBean;
}
```
- 모든 요청에 필터를 적용
  - 필터 안에서 화이트 리스트를 적용해두고 내부 로직으로 걸러냄.
  - 더 이상 registrationBean 자체를 수정하지 않음

### LoginController V4 : 로그인 이후 리다이렉트 처리
```java
    /**
     * 로그인 이후 redirect 처리
     */
    @PostMapping("/login")
    public String loginV4(
            @Valid @ModelAttribute LoginForm form,
            @RequestParam(defaultValue = "/") String redirectURL,
            BindingResult bindingResult,
            HttpServletRequest request) {

        if (bindingResult.hasErrors()) {
            return "login/loginForm";
        }

        Member loginMember = loginService.login(form.getLoginId(), form.getPassword());

        if (loginMember == null) {
            bindingResult.reject("LoginFail", "아이디 또는 패스워드가 맞지 않습니다.");
            return "login/loginForm";
        }

        // TODO : 로그인 성공처리

        // 세션이 있으면 있는 세션 반환(재사용), 없으면 신규 세션을 생성
        HttpSession session = request.getSession();

        // 세션에 로그인 회원 정보 보관
        session.setAttribute(SessionConst.LOGIN_MEMBER, loginMember);
        return "redirect:"+redirectURL;
    }
```
- `RequestParam`으로 리다이렉트 경로 바인딩
  - 디폴트로 "/"
  - 필터로 리다이렉트 시 requestParam에 리다이렉트 url이 바인딩 되서 들어옴
- redirectURL을 이용해서 로그인 성공 시 해당 경로로 고객 redirect 시킴

### 참고
- 필터에서는 chain.doFilter를 호출해서 다음 필터 또는 서블릿 호출 시 request, response를 다른 객체로 바꿀 수 있음
- servletRequest, servletResponse를 구현한 다른 객체를 만들어서 해당 객체가 다음 필터 또는 서블릿에서 사용됨
- 잘 사용되지는 않는 기능.

</div>
</details>

## 7.4 스프링 인터셉터 - 소개
<details>
<summary>접기/펼치기 버튼</summary>
<div markdown="1">

### 7.4.1 스프링 인터셉터의 흐름
```
HTTP 요청 -> WAS -> 필터 -> 서블릿 -> 스프링 인터셉터 -> 컨트롤러
```
- 스프링 인터셉터는 디스패처 서블릿과 컨트롤러 사이에서 컨트롤러 호출 직전에 호출
- 스프링 인터셉터는 스프링 MVC가 제공하는 기능이기 때문에 결국, 디스패처 서블릿 이후에 등장
- **스프링 MVC의 시작점은 사실상 스프링 인터셉터**
- 스프링 인터셉터에도 URL 패턴을 적용할 수 있는데, 서블릿 URL 패턴과는 다르고 매우 정밀하게 사용할 수 있음

### 7.4.2 스프링 인터셉터 제한
```
// 로그인 사용자
HTTP 요청 -> WAS -> 필터 -> 서블릿 -> 스프링 인터셉터 -> 컨트롤러

// 비 로그인 사용자
HTTP 요청 -> WAS -> 필터 -> 서블릿 -> 스프링 인터셉터(적절하지 않은 요청이라 판단, 컨트롤러 호출 x)
```
- 서블릿 필터와 마찬가지로 적절하지 않은 요청이라 판단하면 거기서 끝을 낼 수 있음
- 로그인 여부 체크를 할 때 좋음

### 7.4.3 스프링 인터셉터 체인
```
HTTP 요청 -> WAS -> 필터 -> 서블릿 -> 인터셉터1 -> 인터셉터2 -> ... -> 컨트롤러
```
- 인터셉터 또한 체인으로 구성되고, 중간에 여러 필터를 자유롭게 추가할 수 있음.
  - 예) 로그 인터셉터 - 로그인 여부 체크 인터셉터 - ...
- 여기까지만 놓고보면 서블릿 필터랑 호출 순서만 다르고 기능이 비슷해보이지만, 스프링 인터셉터는 서블릿 필터보다 더 편리하고 정교하고 다양한 기능을 지원함

### 7.4.4 스프링 인터셉터 인터페이스
```java
public interface HandlerInterceptor {
    
	default boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
			throws Exception {
		return true;
	}
    
	default void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
			@Nullable ModelAndView modelAndView) throws Exception {
	}
    
	default void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
			@Nullable Exception ex) throws Exception {
	}
}
```
- `HandlerInterCeptor` 인터페이스 구현
- 서블릿 필터는 단순히 doFilter() 하나만 제공되지만, 스프링 인터셉터는 호출 전, 호출 후, 요청 완료 이후와 같이 단계적으로 세분화되어 있음.
- 서블릿 필터는 단순히 request, response만 제공했지만 인터셉터는 어느 컨트롤러(handler)가 호출되는지에 관한 호출정보, 그리고 어떤 modelAndView가 반환되는지 응답 정보도 받을 수 있음

### 7.4.5 스프링 인터셉터 호출 흐름
- 정상 흐름
  - preHandle : 컨트롤러 호출 전에 호출 (정확히는 핸들러 어댑터 호출 직전)
    - 응답 true : 다음으로
    - 응답 false : 끝 (나머지 인터셉터는 물론이며, 핸들러 어댑터도 호출되지 않음)
  - postHandle : 컨트롤러 호출 후에 호출됨(정확히는 핸들러 어댑터 호출 후 호출됨)
  - afterCompletion : 뷰가 렌더링/API 응답된 이후 실행
- 컨트롤러에서 예외가 발생한 상황
  - preHandle : 컨트롤러 호출 전에 호출
  - postHandle : 컨트롤러에서 예외 발생 시 postHandle이 호출되지 않음.
  - afterCompletion : 항상 호출됨. 이 때, 예외를 parameter로 받아서 어떤 예외가 발생했는 지 로그로 출력할 수 있음.
- **afterCompletion**은 예외가 발생해도 호출된다.
  - 예외가 발생하면 postHandle()이 호출되지 않으므로, 예외와 무관하게 공통적으로 처리하기 위해서는 afterCompletion()을 사용해야한다.
  - 예외가 발생하면 afterCompletion()에 예외 정보(exception)를 포함하여 호출된다.

### 7.4.6 그래서 뭐 써요?
- 인터셉터 : 스프링 MVC 구조에 특화된 필터 기능 제공.
- 스프링MVC를 사용하지 않고 특별히 필터를 사용해야하는 상황이 아니라면 인터셉터를 사용하는 것이 더 편리.
- **웬만해선 인터셉터 쓰자!**

</div>
</details>


## 7.5 스프링 인터셉터 - 요청 로그
<details>
<summary>접기/펼치기 버튼</summary>
<div markdown="1">

### 7.5.1 LogInterceptor - 요청 로그 인터셉터
```java
@Slf4j
public class LogInterceptor implements HandlerInterceptor {

    public static final String LOG_ID = "logId";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        String requestURI = request.getRequestURI();
        String logId = UUID.randomUUID().toString();

        request.setAttribute(LOG_ID, logId);

        // ... 생략
      
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
        log.info("postHandle [{}]", modelAndView);
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        String requestURI = request.getRequestURI();
        String logId = (String) request.getAttribute(LOG_ID);
        log.info("RESPONSE [{}][{}][{}]", logId, requestURI, handler);
        if (ex != null) {
            log.error("afterCompletion error!", ex);
        }
    }
}
```
- `String logId = UUID.randomUUID().toString`
  - 요청 로그를 구분하기 위한 uuid 생성
- `request.setAttribute(LOG_ID, logId)`
  - 서블릿 필터와 달리 스프링 인터셉터에서는 호출 시점이 여러 메서드에 나뉘어 있음. 같은 logId를 여러 메서드에서 공유하기 위해서, request에 담아둠
  - 이후 꺼내 쓸 때는 request.getAttribute(LOG_ID)로 찾아 씀
- return true
  - preHandle 메서드 반환 : true면 정상 호출. 다음 인터셉터나 컨트롤러가 호출 
  
### 7.5.2 HanlerMethod, ResourceHttpRequestHandler
```java
        // @RequestMapping : HandlerMethod
        // 정적 리소스 : ResourceHttpRequestHandler
        if (handler instanceof HandlerMethod) {
            HandlerMethod hm = (HandlerMethod) handler; // 호출할 컨트롤러 메서드의 모든 정보가 포함되어 있음
            // hm을 이용한 로직
        }
        log.info("REQUEST [{}][{}][{}]",logId, requestURI, handler);
```
- **HandlerMethod**
  - Hanler 호출 직전에 preHandle이 호출됨.
  - 스프링을 사용하면 일반적으로 `@Controller`, `@RequestMapping`을 활용한 핸들러 매핑을 사용하는데, 이 때 핸들러 정보로 HandlerMethod가 넘어옴.
- **ResourceHttpRequestHandler**
  - `@Controller`가 아니라 `/resources/static`와 같은 정적 리소스가 호출되는 경우, ResourceHttpRequestHandler가 핸들러 정보로 넘어오기 때문에 타입에 따라서 처리가 필요

### 7.5.3 postHandle, afterCompletion
- 예외가 발생시에는 postHandle이 호출되지 않음
- 예외 발생과 무관하게 afterCompletion은 항상 호출됨이 보장
  - 종료 로그는 afterCompletion에 작성

### 7.5.4 WebConfig - 인터셉터 등록
```java
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new LogInterceptor())
                .order(1)
                .addPathPatterns("/**")
                .excludePathPatterns("/css/**", "/*.ico", "/error");
    }
```
- WebMvcConfigurer를 구현한 클래스를 빈으로 등록
  - addInterceptors : 인터셉터 등록
    - registry.addInterceptor : 인터셉터 추가
    - order : 호출 순서 지정
    - addPathPatterns : 인터셉터를 적용할 url 패턴 지정
    - excludePathPatterns : 인터셉터에서 제외할 url 패턴 지정
- 인터셉터는 필터와 달리 addPathPatterns, excludePathPatterns로 정밀하게 URL 패턴 지정 가능
  - URL 경로 패턴 : [스프링 공식 문서](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/util/pattern/PathPattern.html)

</div>
</details>

## 7.6 스프링 인터셉터 - 인증 체크
<details>
<summary>접기/펼치기 버튼</summary>
<div markdown="1">

### 7.6.1 LoginCheckInterceptor
```java
@Slf4j
public class LoginCheckInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String requestURI = request.getRequestURI();
        log.info("인증 체크 인터셉터 실행 {}", requestURI);

        HttpSession session = request.getSession();

        if (session == null || session.getAttribute(SessionConst.LOGIN_MEMBER) == null) {
            log.info("미인증 사용자 요청");
            response.sendRedirect("/login?redirectURL="+requestURI);
            return false;
        }
        return true;
    }

}
```
- 서블릿 필터 : 요청 URI가 화이트리스트인지 여부를 확인하는 로직이 필요했음
- 스프링 인터셉터 : 인터셉터를 적용하지 않을 URL을 등록시점에서 지정하면 되기 때문에, 인터셉터 내부에서 필터링 로직을 구현하지 않아도 됨
- 인증은 컨트롤러 호출 전에만 호출되면 되므로, preHandle만 구현하면 됨

### 7.6.2 세밀한 설정
```java
@Configuration
public class WebConfig implements WebMvcConfigurer {

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    registry.addInterceptor(new LogInterceptor())
            .order(1)
            .addPathPatterns("/**")
            .excludePathPatterns("/css/**", "/*.ico", "/error");

    registry.addInterceptor(new LoginCheckInterceptor())
            .order(2)
            .addPathPatterns("/**")
            .excludePathPatterns(
                    "/", "/members/add", "/login", "/logout",
                    "/css/**", "/*.ico", "/error"
            );
  }
  
  // 생략
}
```
- 인터셉터를 적용할 URL : addPathPatterns
- 인터셉터를 적용하지 않을 URL : excludePathPatterns

</div>
</details>

## 7.7 ArgumentResolver 활용

---
