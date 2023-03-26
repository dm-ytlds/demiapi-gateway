package com.demi.demiapigateway;

import com.demi.api.utils.SignUtils;
import com.demi.demiapicommon.model.entity.InterfaceInfo;
import com.demi.demiapicommon.model.entity.User;
import com.demi.demiapicommon.service.InnerInterfaceInfoService;
import com.demi.demiapicommon.service.InnerUserInterfaceInfoService;
import com.demi.demiapicommon.service.InnerUserService;
import lombok.extern.slf4j.Slf4j;
import org.apache.dubbo.config.annotation.DubboReference;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * 全局过滤器
 */
@Slf4j
@Component
public class CustomGlobalFilter implements GlobalFilter, Ordered {

    // 引入 Dubbo 远程调用服务
    @DubboReference
    private InnerInterfaceInfoService innerInterfaceInfoService;

    @DubboReference
    private InnerUserService innerUserService;

    @DubboReference
    private InnerUserInterfaceInfoService innerUserInterfaceInfoService;

    private static final List<String> IP_WHITE_LIST = new ArrayList<>();

    // 接口 url 的 host
    private static final String INTERFACE_HOST = "http://localhost:8123";

    /**
     * @param exchange 路由交换机
     * @param chain    责任链
     * @return
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        log.info("全局过滤器中做统一业务处理");

        IP_WHITE_LIST.add("127.0.0.1");
        // 1. 请求日志
        ServerHttpRequest request = exchange.getRequest();
        String url = INTERFACE_HOST + request.getPath().value();
        String method = request.getMethod().toString();
        log.info("请求唯一标识：" + request.getId());

        // 2. 访问控制
        String sourceAccess = Objects.requireNonNull(request.getLocalAddress()).getHostString();
        ServerHttpResponse response = exchange.getResponse();
        if (!IP_WHITE_LIST.contains(sourceAccess)) {
            // 设置状态码 403
            response.setStatusCode(HttpStatus.FORBIDDEN);
            // 结束请求
            return response.setComplete();
        }
        // 3. 用户鉴权（判断 ak sk 是否合法）
        HttpHeaders headers = request.getHeaders();
        String accessKey = headers.get("accessKey").get(0);
        String nonce = headers.get("nonce").get(0);
        String timestamp = headers.get("timestamp").get(0);
        String sign = headers.get("sign").get(0);
        String body = headers.get("body").get(0);
        // 从数据库中获取用户数据
        User invokeUser = null;
        try {
            invokeUser = innerUserService.getInvokeUser(accessKey);
        } catch (Exception e) {
            log.error("获取调用接口的用户数据失败", e);
        }

        if (invokeUser == null) {
            return handleNoAuth(response);
        }
        if (!invokeUser.getAccessKey().equals(accessKey)) {
            return handleNoAuth(response);
        }
        if (Long.parseLong(nonce) > 10001) {
            return handleNoAuth(response);
        }
        // 时间不超过5分钟
        long currentTime = System.currentTimeMillis() / 1000;
        if ((currentTime - Long.parseLong(timestamp)) > 5 * 60) {
            return handleNoAuth(response);
        }
        // 签名
        String sign1 = SignUtils.getSign(body, invokeUser.getSecretKey());
        if (sign1 == null || !sign1.equals(sign)) {
            // 签名不一致
            return handleNoAuth(response);
        }
        // 4. 请求的模拟接口是否存在
        // 从数据库中查询模拟接口是否存在，以及请求方法是否匹配
        InterfaceInfo interfaceInfo = null;
        try {
            interfaceInfo = innerInterfaceInfoService.getInterfaceInfo(url, method);
        } catch (Exception e) {
            log.error("想要调用的接口方法不存在", e);
        }

        if (interfaceInfo == null) {
            handleNoAuth(response);
        }
        // 5. 请求转发，调用模拟接口
        // Mono<Void> filter = chain.filter(exchange);
        // 6. 响应日志
        // 7. 通过用户id和接口id 查询当前接口是否还有调用次数
        // 8. 调用成功，且还有调用次数，接口调用次数 + 1；没有接口调用次数，
        // 8. 调用失败，返回自定义的错误码
        return handleResponse(exchange, chain, interfaceInfo.getId(), invokeUser.getId());
    }

    /**
     * 6. 响应日志
     * 7. 调用成功，接口调用次数 + 1；
     * 8. 调用失败，返回自定义的错误码
     *
     * @param exchange
     * @param chain
     * @return
     */
    public Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain, long interfaceInfoId, long userId) {
        try {
            ServerHttpResponse originalResponse = exchange.getResponse();
            // 封装成数据工厂
            DataBufferFactory bufferFactory = originalResponse.bufferFactory();
            // 获取状态码
            HttpStatus statusCode = originalResponse.getStatusCode();

            if (statusCode == HttpStatus.OK) {
                // 使用 HttpResponse 提供的装饰器，增强数据处理能力
                ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
                    // 等调用完转发的接口后在执行
                    @Override
                    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                        //log.info("body instanceof Flux: {}", (body instanceof Flux));
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                            // 写数据，凭借字符串
                            return super.writeWith(
                                    fluxBody.map(dataBuffer -> {
                                        // 调用成功，接口调用次数 + 1；
                                        try {
                                            innerUserInterfaceInfoService.invokeCount(interfaceInfoId, userId);
                                        }catch (Exception e) {
                                            log.error("接口次数增加失败: ", e);
                                        }

                                        byte[] content = new byte[dataBuffer.readableByteCount()];
                                        dataBuffer.read(content);
                                        DataBufferUtils.release(dataBuffer);//释放掉内存
                                        // 构建日志
                                        StringBuilder sb2 = new StringBuilder(200);
                                        List<Object> rspArgs = new ArrayList<>();
                                        rspArgs.add(originalResponse.getStatusCode());
                                        //rspArgs.add(requestUrl);
                                        String data = new String(content, StandardCharsets.UTF_8);//data
                                        sb2.append(data);
                                        log.info(sb2.toString(), rspArgs.toArray());//log.info("<-- {} {}\n", originalResponse.getStatusCode(), data);
                                        return bufferFactory.wrap(content);
                                    }));
                        } else {

                            // 调用失败，返回自定义的错误码
                            log.error("<--- {} 响应code异常", getStatusCode());
                        }
                        return super.writeWith(body);
                    }
                };
                return chain.filter(exchange.mutate().response(decoratedResponse).build());
            }
            return chain.filter(exchange);//降级处理返回数据
        } catch (Exception e) {
            log.error("网关处理响应异常：\n" + e);
            return chain.filter(exchange);
        }
    }

    @Override
    public int getOrder() {
        return -1;
    }

    /**
     * 调用接口时，用户权限认证
     *
     * @param response
     * @return
     */
    public Mono<Void> handleNoAuth(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    public Mono<Void> handleInvokeError(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }
}