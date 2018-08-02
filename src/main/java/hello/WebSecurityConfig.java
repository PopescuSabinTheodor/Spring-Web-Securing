package hello;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.filter.CompositeFilter;
import org.springframework.web.servlet.ModelAndView;

@Configuration
@EnableOAuth2Client
@EnableWebSecurity
@RestController
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	OAuth2ClientContext oauth2ClientContext;

	@Autowired
	private UserRepository userRepository;

	@RequestMapping({ "/user", "/me" })
	public Principal user(Principal principal) {
		return principal;
	}

	@ResponseBody
	@RequestMapping("/users")
	public Iterable<hello.User> dbList() {
		return userRepository.findAll();
	}

	

	@Bean
	public FilterRegistrationBean<OAuth2ClientContextFilter> oauth2ClientFilterRegistration(
			OAuth2ClientContextFilter filter) {
		FilterRegistrationBean<OAuth2ClientContextFilter> registration = new FilterRegistrationBean<OAuth2ClientContextFilter>();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

	@Bean
	@ConfigurationProperties("google")
	public ClientResources google() {
		return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("facebook")
	public ClientResources facebook() {
		return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("github")
	public ClientResources github() {
		return new ClientResources();
	}

	/**
	 * Add filters for authentication
	 * 
	 * @return a {@link CompositeFilter}
	 */
	private Filter ssoFilter() {
		CompositeFilter filter = new CompositeFilter();
		List<Filter> filters = new ArrayList<>();
		filters.add(ssoFilter(facebook(), "/login/facebook"));
		filters.add(ssoFilter(google(), "/login/google"));
		filters.add(ssoFilter(github(), "/login/github"));
		filter.setFilters(filters);
		return filter;
	}

	/**
	 * Build an authentication filter
	 * 
	 * @param client
	 * @param path
	 * @return An {@link OAuth2ClientAuthenticationProcessingFilter}
	 */
	private Filter ssoFilter(ClientResources client, String path) {
		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
		OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
		filter.setRestTemplate(template);
		CustomToken tokenServices = new CustomToken(client.getResource().getUserInfoUri(),
				client.getClient().getClientId(), userRepository);
		tokenServices.setRestTemplate(template);
		tokenServices.setProvider(client.getResource().getUserInfoUri());
		filter.setTokenServices(tokenServices);
		return filter;
	}

	class ClientResources {

		@NestedConfigurationProperty
		private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

		@NestedConfigurationProperty
		private ResourceServerProperties resource = new ResourceServerProperties();

		public AuthorizationCodeResourceDetails getClient() {
			return client;
		}

		public ResourceServerProperties getResource() {
			return resource;
		}
	}

	/**
	 * Configure security for user interface
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.antMatcher("/**").authorizeRequests()
				.antMatchers("/", "/home", "/dispatch", "loginFrom", "/login/google", "/login/facebook",
						"/login/github", "/users", "/images/**", "/*.png")
				.permitAll().anyRequest().authenticated().and().exceptionHandling().and().formLogin()
				.loginPage("/loginForm").defaultSuccessUrl("/hello").permitAll().and().logout()
				.logoutSuccessUrl("/dispatch").and().csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
				.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
	}

	@Bean
	@Override
	public UserDetailsService userDetailsService() {
		@SuppressWarnings("deprecation")
		UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER")
				.build();

		return new InMemoryUserDetailsManager(user);
	}
}