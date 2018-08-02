package hello;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * User model
 * 
 * @author intern1
 *
 */
@Entity
@Table(name = "user")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	/**
	 * The user's unique identifier
	 */
	Integer userId;
	/**
	 * The user's email address
	 */
	String email;
	/**
	 * The user's name
	 */
	String name;
	/**
	 * The user's unique identifier on the application that he authenticated with
	 */
	String appId;
	/**
	 * The application used to authenticate
	 */
	String app;

	public String getApp() {
		return app;
	}

	public void setApp(String app) {
		this.app = app;
	}

	public Integer getUserId() {
		return userId;
	}

	public void setUserId(Integer userId) {
		this.userId = userId;
	}

	public String getEmail() {

		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getAppId() {
		return appId;
	}

	public void setAppId(String appId) {
		this.appId = appId;
	}

}
