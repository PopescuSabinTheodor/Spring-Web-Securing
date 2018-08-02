package hello;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

@PasswordMatches
public class UserDto {

	@NotNull
	@NotEmpty
	String firstName;
	
	@NotNull
	@NotEmpty
	String lastName;
	
	@ValidEmail
	@NotNull
	@NotEmpty
	String email;
	
	@NotNull
	@NotEmpty
	String password;
	String matchingPassword;
	
	public String getFirstName() {
		return firstName;
	}
	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}
	public String getLastName() {
		return lastName;
	}
	public void setLastName(String lastName) {
		this.lastName = lastName;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getMatchingPassword() {
		return matchingPassword;
	}
	public void setMatchingPassword(String matchingPassword) {
		this.matchingPassword = matchingPassword;
	}
}
