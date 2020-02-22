package com.ekam.spring.security.multiAuthSecurityApp.controllers;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UnprotectedController {

    @RequestMapping("/unprotected")
    public @ResponseBody String getSecurityFilterChainProxy1(){
        return "this page is unprotected";
    }

}
