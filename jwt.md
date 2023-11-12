# JWT	（JSON Web Token）

## 1.	在pom.xml引入JWT依赖

```xml
 <!--        jwt-->
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.4.0</version>
</dependency>
```

## 2.	第一个JWT例子

```java
void jwtTokenEg() {
    Map<String, Object> map = new HashMap<>();
    // 创建token生效的时间
    Calendar instance = Calendar.getInstance();
    instance.add(Calendar.SECOND, 9000);

    String token = JWT.create()
            .withHeader(map)
            .withClaim("username", "FirstSnow")
            .withClaim("price", "1000")
            .withExpiresAt(instance.getTime())
            .sign(Algorithm.HMAC256("#F?S&Token!"));

    System.out.println(token);
}
```

```txt
// 打印出来的值
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwcmljZSI6IjEwMDAiLCJleHAiOjE2OTk3ODA1NzMsInVzZXJuYW1lIjoiRmlyc3RTbm93In0.Txi7OHJQFBLyA4QTCcj8Hj1k5ZnA2wAfyeSh-2tQgtU
```

## 3.	解密之后的值	([JSON Web Tokens - jwt.io](https://jwt.io/))

```JSON
// HEADER
{
  "typ": "JWT",
  "alg": "HS256"
}
```

```JSON
// PAYLOAD
{
  "price": "1000",
  "exp": 1699780573,
  "username": "FirstSnow"
}
```

```JSON
// VERIFY SIGNATURE
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  your-256-bit-secret
) secret base64 encoded
```

## 4.	获取存储的值

```java
@Test
public void JwtTestOpen() {
    JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256("#F?S&Token!")).build();

    DecodedJWT verify = jwtVerifier.verify(上面生成的token);

    System.out.println(verify.getClaims().get("username").asString());
    System.out.println(verify.getClaims().get("price").asString());
    // token的过期时间
    System.out.println(verify.getExpiresAt());

}
```

## 5.	常见的异常错误

```markdown
//	签名不一致异常
SignatureVerificationException
//	令牌过期异常
TokenExpiredException 
//	算法不匹配异常
AlgorithmMismatchException 
//	失效的payload异常（传给客户端后，token被改动，验证不一致）
InvalidClaimException 
```

## 6.	工具类的封装

```java
package com.demo.jwtdemo.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.Map;

public class JwtUtils {

    private static final String SING = "!FIRST%W#Y#@VNS(^uIJS)*SON";

    /**
     * 返回 token
     * @param map
     * @return
     */
    public static String getToken(Map<String, String> map) {

        Calendar instance = Calendar.getInstance();
        // 默认 7 天过期
        instance.add(Calendar.DATE, 7);

        // 创建 JWT builder
        JWTCreator.Builder builder = JWT.create();

        // payload
        map.forEach(builder::withClaim);

        String token = builder.withExpiresAt(instance.getTime())
                .sign(Algorithm.HMAC256(SING));

        return token;
    }

    /**
     * 验证 token 的合理性
     * @param token
     * @return
     */
    public static DecodedJWT verify(String token){
        return JWT.require(Algorithm.HMAC256(SING)).build().verify(token);
    }

}

```

## 7.	拦截器实现不同用户登录的验证思路

```java
public class AuthorizationInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 获取当前用户的身份信息，这里假设用户信息保存在 session 中
        User currentUser = (User) request.getSession().getAttribute("currentUser");
        
        // 根据用户身份信息进行权限判断
        if (currentUser == null) {
            // 用户未登录，拦截请求
            response.sendRedirect("/login");
            return false;
        } else if (currentUser.getRole().equals("admin")) {
            // 管理员可以访问所有接口，不做拦截
            return true;
        } else if (currentUser.getRole().equals("user")) {
            // 普通用户只能访问部分接口，需要进行接口权限判断
            String requestURI = request.getRequestURI();
            if (requestURI.startsWith("/user")) {
                // 允许用户访问 /user 开头的接口
                return true;
            } else {
                // 其他接口拦截
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
                return false;
            }
        }
        return true;
    }
}

```

## 8.	拦截器实现JWT

这里写的比较简陋，理论上这个异常应该交给异常处理

```java
package com.demo.jwtdemo.interceptor;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.demo.jwtdemo.utils.JwtUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

public class JWTInterceptor implements HandlerInterceptor {

    private static final String TYPE = "application/json;charset=UTF-8";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
//        return HandlerInterceptor.super.preHandle(request, response, handler);
        Map<String, Object> map = new HashMap<>();

        //  获取请求头中的token令牌
        String token = request.getHeader("token");

        try {
            JwtUtils.verify(token);
            return true;
        } catch (SignatureVerificationException e) {
            e.printStackTrace();
            map.put("msg", "无效签名");
        } catch (TokenExpiredException e) {
            e.printStackTrace();
            map.put("msg", "令牌过期异常");
        } catch (AlgorithmMismatchException e) {
            e.printStackTrace();
            map.put("msg", "令牌算法不匹配");
        } catch (InvalidClaimException e) {
            e.printStackTrace();
            map.put("msg", "失效的payload异常（传给客户端后，token被改动，验证不一致）");
        } catch (Exception e) {
            e.printStackTrace();
            map.put("msg", "token过期");
        }
        map.put("msg", false);
        String json = new ObjectMapper().writeValueAsString(map);
        response.setContentType(TYPE);
        response.getWriter().println(json);
        return false;
    }
}

```

## 9.	使拦截器生效

```java
package com.demo.jwtdemo.config;

import com.demo.jwtdemo.interceptor.JWTInterceptor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Component
public class JWTConfig implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
//        WebMvcConfigurer.super.addInterceptors(registry);
        registry.addInterceptor(new JWTInterceptor())
                .addPathPatterns("/user/test")
                .excludePathPatterns("/user/login");
    }
}
```

