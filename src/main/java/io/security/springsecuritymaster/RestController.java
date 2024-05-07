package io.security.springsecuritymaster;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@org.springframework.web.bind.annotation.RestController
public class RestController {

    @GetMapping("/")
    public String index(){
        return "index";
    }

    @GetMapping("/custom")
    public String custom(){
        return "custom";
    }

    @GetMapping("/user/{name}")
    public String userName(@PathVariable(value = "name") String name){
        return name;
    }

    @GetMapping("/admin/db")
    public String admin(){
        return "admin";
    }

    @GetMapping("/api/photos")
    public String photos(){
        return "photos";
    }

    @GetMapping("/oauth/login")
    public String oauth(){
        return "oauthLogin";
    }
}
