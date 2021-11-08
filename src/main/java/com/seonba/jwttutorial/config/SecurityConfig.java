package com.seonba.jwttutorial.config;


import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


//기본적인 Web 보안을 활성화 하겠다는 뜻
// 추가적인 설정을 하기 위해 WebSecurityConfigurer를 implements하거나,
// WebSecurityConfigurerAdapter 를 extends하는 방법이 있다.
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurity web){
        web
                .ignoring()
                .antMatchers(
                        "/h2-console/**"
                        //파비콘 관련 요청과 h2 관련 요청은 그냥 Security 무시
                        ,"favicon.ico"
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //HttpServletRequest를 사용하는 요청들에 대한 접근제한을 설정하겠다는 의미
                .authorizeRequests()
                //이 요청에대한 접근은 인증 없이 접근을 허용하겠다
                .antMatchers("/api/hello").permitAll()
                //나머지 요청들에 대해서는 모두 인증을 받아야 한다.
                .anyRequest().authenticated();
    }
}
