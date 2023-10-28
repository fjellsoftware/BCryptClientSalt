// Copyright (c) 2023 Fjell Software AS
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package com.fjellsoftware.bcryptclientsalt;

import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * BCryptClientSalt is a utility for creating deterministic salts for use with BCrypt. This allows clients to ask a
 * server for the salt and then perform the BCrypt hashing on a password before sending the hashed password over the
 * wire to the server. This prevents the server from accidentally leaking the plaintext password, as well as putting
 * the burden of performing the hashing work on to the client.
 * <p>
 * Generating the salt works by supplying a service identifier, for example a fully qualified domain name like
 * retail-demo.loppi.io, and a service-unique username, for example john_doe_465 or john.doe@loppi.io. These two strings
 * are concatenated, and then hashed with SHA-256, and from the result, the first 16 bytes are extracted and then
 * encoded with BCrypt's special Base64 encoding.
 * <p>
 * When using this library, a typical login flow might look like:
 * <pre>{@code
 * public static void main(String[] args){
 * 	login("john.doe@example.com", "horsestaplepassword");
 * }
 *
 * // Client side
 *
 * public boolean login(String username, String password){
 * 	String salt = fetchBCryptSalt();
 * 	String hashedPassword = BCrypt.hashpw(password, salt);
 * 	return doHttpPostLogin(username, hashedPassword);
 * }
 *
 * private String fetchBCryptSalt(String username){
 * 	createBCryptSalt(username)
 * }
 *
 * private boolean doHttpPostLogin(String username, String hashedPassword){
 * 	checkLoginValid(username, hashedPassword);
 * }
 *
 *
 * // Server side
 *
 * //change me
 * private static final String hostName = "example.com";
 * public void createBCryptSalt(String username){
 * 	String salt = BCryptClientSalt.fromServiceIdentifierAndUsername(hostName, username);
 * }
 *
 * public boolean checkLoginValid(String username, String inputHashedPassword_BCrypt){
 * 	byte[] passwordFromDatabase_BCrypt_SHA256 = fetchPasswordFromDatabase(username);
 * 	byte[] inputHashedPassword_BCrypt_SHA256 = sha256Hash(bcryptHashedPassword);
 * 	return Arrays.equals(passwordFromDatabase_BCrypt_SHA256, inputHashedPassword_BCrypt_SHA256);
 * }
 *
 * private byte[] fetchPasswordFromDatabase(String username){
 * 	//implement
 * }
 *
 * private byte[] sha256Hash(String textToHash){
 * 	//implement
 * }
 * }</pre>
 */

public class BCryptClientSalt {

    private static final int BCRYPT_SALT_LEN = 16;
    private static final int DEFAULT_LOG_ROUNDS = 14;

    private static final MessageDigest sha256Digest = createSHA256MessageDigest();
    private static MessageDigest createSHA256MessageDigest(){
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to initialize SHA-256 message digest.", e);
        }
    }

    /**
     * Generate a deterministic salt for use with BCrypt based on a service identifier and a service-unique username.
     * @param serviceIdentifier     the identifier for the service, for example a fully qualified domain name like
     *                              retail-demo.loppi.io
     * @param username              the service-unique username
     * @param logRounds             the log2 of the number of rounds of hashing to apply - the work factor therefore
     *                              increases as 2**log_rounds.
     * @return	an encoded salt value
     */
    public static @NotNull String fromServiceIdentifierAndUsername(
            @NotNull String serviceIdentifier, @NotNull String username, int logRounds){
        if (logRounds < 4 || logRounds > 30) {
            throw new IllegalArgumentException("Bad number of rounds");
        }
        Objects.requireNonNull(serviceIdentifier);
        Objects.requireNonNull(username);
        StringBuilder rs = new StringBuilder();
        byte[] stringBytes = (serviceIdentifier + username).getBytes(StandardCharsets.UTF_8);
        byte[] digest = sha256Digest.digest(stringBytes);
        rs.append("$2a$");
        rs.append(logRounds);
        rs.append("$");
        rs.append(BCrypt.encode_base64(digest, BCRYPT_SALT_LEN));
        return rs.toString();
    }

    /**
     * Generate a deterministic salt for use with BCrypt based on a service identifier and a service-unique username.
     * Uses 14 as the log2 rounds of hashing.
     * @param serviceIdentifier     the identifier for the service, for example a fully qualified domain name like
     *                              retail-demo.loppi.io
     * @param username              the service-unique username
     * @return	an encoded salt value
     */
    public static @NotNull String fromServiceIdentifierAndUsername(
            @NotNull String serviceIdentifier, @NotNull String username){
        return fromServiceIdentifierAndUsername(serviceIdentifier, username, DEFAULT_LOG_ROUNDS);
    }
}
