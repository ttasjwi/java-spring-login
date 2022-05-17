
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

## 7.4 스프링 인터셉터 - 소개

## 7.5 스프링 인터셉터 - 요청 로그

## 7.6 스프링 인터셉터 - 인증 체크

## 7.7 ArgumentResolver 활용

---
