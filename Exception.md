# Exception	异常处理

## 1.	统一返回 

```java
package com.demo.jwtdemo.config;

import com.demo.jwtdemo.exception.AppExceptionCodeMsg;
import lombok.Data;

import java.io.Serializable;

@Data
public class Result<T> implements Serializable {
    private int code;
    private String msg;
    private T data;



    private Result(int code, String msg, T data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }


    public static <T> Result<T> returnData(int code, String msg, T data) {

        Result<T> result = new Result<>(code,msg,data);

        result.setCode(code);
        result.setMsg(msg);
        result.setData(data);

        return result;
    }

    public static <T> Result<T> success() {
        return returnData(200, "success", null);
    }

    public static <T> Result<T> success(T data) {
        return returnData(200, "success", data);
    }

    public static <T> Result<T> error(AppExceptionCodeMsg appExceptionCodeMsg) {
        return returnData(appExceptionCodeMsg.getCode(), appExceptionCodeMsg.getMsg(), null);
    }

    public static <T> Result<T> error(int code, String msg) {
        return returnData(code, msg, null);
    }

}

```

## 2.	全局异常探测

```java
package com.demo.jwtdemo.exception;

import com.demo.jwtdemo.config.Result;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(value = {Exception.class})
    @ResponseBody
    public <T> Result<T> exceptionHandler(Exception e) {
        // 这里先判断拦截到的Exception是不是我们自己定义的异常类型
        if (e instanceof AppException){
            AppException appException = (AppException) e;
            return Result.error(appException.getCode(),appException.getMsg());
        }
        // 反之出去,爱怎么报错怎么报错,不归我管.
        return Result.error(500,"服务器异常");
    }

}

```

## 3.	自定义异常	（RuntimeException）

```java
package com.demo.jwtdemo.exception;

public class AppException extends RuntimeException{

    private int code = 500;

    private String msg = "服务器异常";

    public AppException(AppExceptionCodeMsg appExceptionCodeMsg) {
        super();
        this.code = appExceptionCodeMsg.getCode();
        this.msg = appExceptionCodeMsg.getMsg();
    }

    public AppException(int code, String msg){
        super();
        this.msg = msg;
        this.code = code;
    }

    public int getCode(){
        return code;
    }

    public String getMsg(){
        return msg;
    }
}

```

## 4.	创建一个枚举类型，自定义业务异常返回

```java
package com.demo.jwtdemo.exception;

public enum AppExceptionCodeMsg {

    INVALID_PARAM(10000, "参数不合法"),
    USERNAME_NOT_EXISTS(10001, "用户名不存在");

    private int code;

    private String msg;

    public int getCode() {
        return code;
    }

    public String getMsg() {
        return msg;
    }

    AppExceptionCodeMsg(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }
}

```

## 5.	简单示例

```java
package com.demo.jwtdemo.controller;

import com.demo.jwtdemo.config.Result;
import com.demo.jwtdemo.exception.AppException;
import com.demo.jwtdemo.exception.AppExceptionCodeMsg;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {

    @GetMapping("/test")
    public Result<String> test(String name) {
        if (name == null) {
            throw new AppException(AppExceptionCodeMsg.INVALID_PARAM);
        }
        return Result.success("hello " + name);
    }

}

```

