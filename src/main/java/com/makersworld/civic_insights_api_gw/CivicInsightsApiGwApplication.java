package com.makersworld.civic_insights_api_gw;

import com.makersworld.civic_insights_api_gw.config.JwtConfigProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(JwtConfigProperties.class)
public class CivicInsightsApiGwApplication {

	public static void main(String[] args) {
		SpringApplication.run(CivicInsightsApiGwApplication.class, args);
	}

}
