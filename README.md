
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
