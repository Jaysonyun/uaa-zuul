package com.hfcsbc.config;

import com.hfcsbc.security.DomainUserDetailsService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import javax.annotation.Resource;
import javax.jws.soap.SOAPBinding;
import javax.sql.DataSource;

import java.security.KeyPair;

/**
 * Created by wangyunfei on 2017/6/9.
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private TokenStore tokenStore;
//	@Autowired
//	private RedisConnectionFactory connectionFactory;
    @Resource(name = "userDetailsService")
    private UserDetailsService userDetailsService;


//	@Bean
//	public RedisTokenStore tokenStore() {
//		return new RedisTokenStore(connectionFactory);
//	}
//	
//	@Bean
//	public DomainUserDetailsService domainUserDetailsService() {
//		return new DomainUserDetailsService();
//	}

//	@Override
//	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//		endpoints.authenticationManager(authenticationManager).userDetailsService(userDetailsService)//若无，refresh_token会有UserDetailsService is required错误
//				.tokenStore(tokenStore());
//	}
//	

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)//若无，refresh_token会有UserDetailsService is required错误
                .tokenStore(tokenStore());
	}
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()")
//		.allowFormAuthenticationForClients()
		;
	    //enable client to get the authenticated when using the /oauth/token to get a access token  
	    //there is a 401 authentication is required if it doesn't allow form authentication for clients when access /oauth/token  
//		security.allowFormAuthenticationForClients();  
	}
	static final String SCOPE_READ = "read";
	static final String SCOPE_WRITE = "write";
	static final String TRUST = "trust";
	static final int ACCESS_TOKEN_VALIDITY_SECONDS = 1*60*60;
    static final int FREFRESH_TOKEN_VALIDITY_SECONDS = 6*60*60;
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		
		clients.inMemory()
//				.withClient("android").scopes("xx").secret("android")
//				.authorizedGrantTypes("password", "authorization_code", "refresh_token")
//				.and().withClient("admin").scopes("xx").secret("admin")
//				.authorizedGrantTypes("password", "authorization_code", "refresh_token")
//				
//				.and()
				
				.withClient("webapp").secret("secret")
				.authorizedGrantTypes("password", "authorization_code", "refresh_token")
//				.authorizedGrantTypes("implicit")
				
				.scopes(SCOPE_READ, SCOPE_WRITE, TRUST)
				.accessTokenValiditySeconds(ACCESS_TOKEN_VALIDITY_SECONDS).
				refreshTokenValiditySeconds(FREFRESH_TOKEN_VALIDITY_SECONDS);
				
				
				
				;
		
		
	}
	


}
