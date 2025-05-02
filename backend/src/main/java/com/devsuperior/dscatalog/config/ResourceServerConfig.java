package com.devsuperior.dscatalog.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;



@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter{

	@Autowired
	private Environment env;
	
	@Autowired
	private JwtTokenStore tokenStore; 
	
	private static final String[] PUBLIC = { "/oauth/token", "/h2-console/**" };
	
	private static final String[] OPERATOR_OR_ADMIN = { "/products/**", "/categories/**" };	
	
	private static final String[] ADMIN = { "/users/**" };
	
	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources.tokenStore(tokenStore);
	}
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
		
		// Liberar o H2
		if (Arrays.asList(env.getActiveProfiles()).contains("test")){
			http.headers().frameOptions().disable();
			
		}
		
		http.authorizeRequests() //iniciar as configurações de autorizações
		.antMatchers(PUBLIC).permitAll() //Define autoriza~çoes de rota PUBLIC
		.antMatchers(HttpMethod.GET, OPERATOR_OR_ADMIN).permitAll() //Liberar o metodo GET para o vetor OPERATOR_OR_ADMIN
		.antMatchers(OPERATOR_OR_ADMIN).hasAnyRole("OPERATOR", "ADMIN")//As rotas do vetor OPERATOR_OR_ADMIN tera acesso que tiver os Role "OPERADOR" ou "ADMIN." 
		.antMatchers(ADMIN).hasRole("ADMIN")//O vetor ADMIN só pode acessar que tiver logado com perfil "ADMIN"
		.anyRequest().authenticated();//Qualquer outra rota não especificada tem que tar logado, não importa o perfil de usuário.
		
		http.cors().configurationSource(corsConfigurationSource());
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration corsConfig = new CorsConfiguration();
		corsConfig.setAllowedOriginPatterns(Arrays.asList("*"));//Com * esta liberando todos, quando estiver no servidor informar a url aqui
		corsConfig.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE", "PATCH"));
		corsConfig.setAllowCredentials(true);
		corsConfig.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
		
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", corsConfig);
		
		return source;
	}
	
	@Bean
	public FilterRegistrationBean<CorsFilter> corsFilter(){
		FilterRegistrationBean<CorsFilter> bean
			= new FilterRegistrationBean<>(new CorsFilter(corsConfigurationSource()));
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
		return bean;
	}
	
}





