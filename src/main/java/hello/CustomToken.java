package hello;

import java.util.ArrayList;
import java.util.Map;

import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

public class CustomToken extends UserInfoTokenServices {

	private UserRepository userRepository;

	private String provider;

	/**
	 * Constructor
	 * 
	 * @param userInfoEndpointUrl
	 * @param clientId
	 * @param userRepository
	 */
	public CustomToken(String userInfoEndpointUrl, String clientId, UserRepository userRepository) {
		super(userInfoEndpointUrl, clientId);
		this.userRepository = userRepository;
	}

	/**
	 * Check if there is already a record in the database with the appId
	 * 
	 * @param appId The user's id within the application he authenticated with
	 * @return true if appId exists in the database and false otherwise
	 */
	public boolean CheckIfExists(String appId) {
		Iterable<User> userList = new ArrayList<User>();
		userList = userRepository.findAll();
		for (User dbUser : userList) {
			if (dbUser.getAppId().equals(appId)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Authenticates a user and if there is no record of him in the database, it
	 * inserts one
	 * 
	 * @return an authentication
	 */
	@Override
	public OAuth2Authentication loadAuthentication(String accessToken)
			throws AuthenticationException, InvalidTokenException {

		OAuth2Authentication loadAuthentication = super.loadAuthentication(accessToken);
		@SuppressWarnings("unchecked")
		Map<String, Object> map = (Map<String, Object>) loadAuthentication.getUserAuthentication().getDetails();
		String id = String.valueOf(map.get("id"));
		String email = String.valueOf(map.get("email"));

		if (!CheckIfExists(id)) {
			User n = new User();
			n.setAppId(id);
			n.setEmail(email);
			if (this.provider.contains("github")) {
				n.setApp("Github");
				n.setName(String.valueOf(map.get("login")));
			} else if (this.provider.contains("facebook")) {
				n.setName(String.valueOf(map.get("name")));
				n.setApp("Facebook");
			} else {
				n.setName(String.valueOf(map.get("name")));
				n.setApp("Google");
			}
			userRepository.save(n);
		}
		return loadAuthentication;
	}

	/**
	 * Getter
	 * 
	 * @return provider
	 */
	public String getProvider() {
		return provider;
	}

	/**
	 * Setter
	 * 
	 * @param userInfoUri The API address used to gather data from the authenticated
	 *                    user
	 */
	public void setProvider(String userInfoUri) {
		this.provider = userInfoUri;
	}

}
