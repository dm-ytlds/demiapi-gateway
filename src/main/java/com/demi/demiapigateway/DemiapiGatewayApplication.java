package com.demi.demiapigateway;


import com.demi.provider.DemoService;
import org.apache.dubbo.config.annotation.DubboReference;
import org.apache.dubbo.config.spring.context.annotation.EnableDubbo;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Service;

@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
@EnableDubbo
@Service
public class DemiapiGatewayApplication {

    @DubboReference
    private DemoService demoService;

    public static void main(String[] args) {
        ConfigurableApplicationContext context = SpringApplication.run(DemiapiGatewayApplication.class, args);
        DemiapiGatewayApplication demi = context.getBean(DemiapiGatewayApplication.class);
        String world = demi.doSayHello("world");
        System.out.println(world);

    }

    public String doSayHello(String name) {
        return demoService.sayHello(name);
    }
    


}
