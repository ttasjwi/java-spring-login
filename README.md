
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
