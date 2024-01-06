package com.jeevith.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

//@RestController
public class ControllerClass1 {
	
	@GetMapping( path = "msg")
	public String sayMessage() {
		return "Hello There " ;
	}
}
