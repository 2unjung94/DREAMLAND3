package com.dreamland.prj;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class DreamlandApplication {

	public static void main(String[] args) {
		SpringApplication.run(DreamlandApplication.class, args);
	}

}
