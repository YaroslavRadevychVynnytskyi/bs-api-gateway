package com.application.bsapigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class BsApiGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(BsApiGatewayApplication.class, args);
    }

}
