
## java-spring-login

- 인프런 김영한님의 '스프링 MVC 2편 - 백엔드 웹개발 활용 기술' 강의
- 로그인 구현 학습을 위한 Repository

---

## 로그인/로그아웃 - 쿠키 기반

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

### 스프링(@SessionAttribute)

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
