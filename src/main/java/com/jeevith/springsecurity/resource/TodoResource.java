package com.jeevith.springsecurity.resource;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TodoResource {
	
	private Logger logger = LoggerFactory.getLogger(getClass()) ;
	
	private static final List<Todo> Todo_list = List.of(new Todo("jeevith", "Learn Java"),
			                                            new Todo("san", "Learn Accountance"),
			                                            new Todo("jeevith", "Learn docker")) ;
	
	@GetMapping(path = "todos")
	public List<Todo> retriveAllTodos(){
		return Todo_list ;
	}
	
	
	@GetMapping("/users/{username}/todos")
	@PreAuthorize("hasRole('USER')and  #username == authentication.name")
	public Todo retriveTodoForSpecificTodo(@PathVariable String username) {
		return Todo_list.get(0) ;
			
	}
	
	@PostMapping("/users/{username}/todos")
	public void createTodoForSpecificTodos(@PathVariable String username, 
			                               @RequestBody Todo todo) {
		logger.info("Create {} for {}", todo, username ) ;
			
	}
}
