BCrypt client salt utility
====================

<p>BCryptClientSalt is a java utility for creating deterministic salts for use with BCrypt. This allows clients to ask a 
server for the salt and then perform the BCrypt hashing on a password before sending the hashed password over the 
wire to the server. This prevents the server from accidentally leaking the plaintext password, as well as putting the 
burden of performing the hashing work on the client.</p>

<p>Generating the salt works by supplying a service identifier, for example a fully qualified domain name like 
retail-demo.loppi.io, and a service-unique username, for example john_doe_465 or john.doe@loppi.io. 
These two strings are concatenated, and then hashed with SHA-256, and from the result, the first 16 bytes are 
extracted and then encoded with BCrypt's special Base64 encoding.</p>

<p>When using this library, a typical login flow might look like:</p>

```java
public class ClientSaltDemonstration {
  public static void main(String[] args){
    login("john.doe@example.com", "horsestaplepassword");
  }
 
  // Client side
 
  public boolean login(String username, String password){
  	String salt = fetchBCryptSalt();
  	String hashedPassword = BCrypt.hashpw(password, salt);
  	return doHttpPostLogin(username, hashedPassword);
  }
 
  private String fetchBCryptSalt(String username){
  	createBCryptSalt(username);
  }
 
  private boolean doHttpPostLogin(String username, String hashedPassword){
  	checkLoginValid(username, hashedPassword);
  }
 
 
  // Server side
 
  //change me
  private static final String hostName = "example.com";
  public void createBCryptSalt(String username){
  	String salt = BCryptClientSalt.fromServiceIdentifierAndUsername(hostName, username);
  }
 
  public boolean checkLoginValid(String username, String inputHashedPassword_BCrypt){
  	byte[] passwordFromDatabase_BCrypt_SHA256 = fetchPasswordFromDatabase(username);
  	byte[] inputHashedPassword_BCrypt_SHA256 = sha256Hash(bcryptHashedPassword);
  	return Arrays.equals(passwordFromDatabase_BCrypt_SHA256, inputHashedPassword_BCrypt_SHA256);
  }
 
  private byte[] fetchPasswordFromDatabase(String username){
  	//implement
  }
 
  private byte[] sha256Hash(String textToHash){
  	//implement
  }
}
```
