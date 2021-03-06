package com.lmm.springsecurityoauth2.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

/**
 * @author minmin.liu
 * @version 1.0
 */
@Configuration
@Slf4j
public class OAuth2ServerConfig {

  private static final String DEMO_RESOURCE_ID = "order";

  @Configuration
  @EnableResourceServer
  protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
      resources.resourceId(DEMO_RESOURCE_ID).stateless(true);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
      http
          .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
          .and()
          .requestMatchers().anyRequest()
          .and()
          .anonymous()
          .and()
          .authorizeRequests()
          .antMatchers("/order/**").authenticated();
    }
  }

  @Configuration
  @EnableAuthorizationServer
  protected static class AuthorizationServerConfiguration extends
      AuthorizationServerConfigurerAdapter {

    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    RedisConnectionFactory redisConnectionFactory;
    @Autowired
    BCryptPasswordEncoder passwordEncoder;

//     ??????OAuth2????????????????????????
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
      String finalPassword = passwordEncoder.encode("123456");
      log.error("pwd:{}", finalPassword);

      clients.inMemory().withClient("client_1")
          .resourceIds(DEMO_RESOURCE_ID)
          .authorizedGrantTypes("client_credentials", "refresh_token")
          .scopes("select")
          .authorities("oauth2")
          .secret(finalPassword)
          .and().withClient("client_2")
          .resourceIds(DEMO_RESOURCE_ID)
          .authorizedGrantTypes("password", "refresh_token")
          .scopes("select")
          .authorities("oauth2")
          .secret(finalPassword);
    }

    /**
     * ??????AuthorizationServerEndpointsConfigurer??????????????????
     * ???????????????????????????????????????????????????TokenStore???TokenGranter???OAuth2RequestFactory
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
      endpoints.tokenStore(new RedisTokenStore(redisConnectionFactory))
          .authenticationManager(authenticationManager)
          .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
    }

//    ??????AuthorizationServer????????????????????????????????????ClientCredentialsTokenEndpointFilter???????????????
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
      //??????????????????
      security.allowFormAuthenticationForClients();
    }
  }
}
