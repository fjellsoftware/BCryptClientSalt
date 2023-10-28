package com.fjellsoftware.bcryptclientsalt;


import org.junit.jupiter.api.Test;

public class TestClientSalt {

    @Test
    public void fromServiceIdentifierAndUsername(){
        // Checks salt generation is deterministic and doesn't collide with a couple examples
        String serviceJohn1 = BCryptClientSalt
                .fromServiceIdentifierAndUsername("service.fjellsoftware.com", "john.doe@mail.com");
        String serviceJohn2 = BCryptClientSalt
                .fromServiceIdentifierAndUsername("service.fjellsoftware.com", "john.doe@mail.com");
        String otherServiceJohn = BCryptClientSalt
                .fromServiceIdentifierAndUsername("other-service.fjellsoftware.com", "john.doe@mail.com");
        String serviceDave = BCryptClientSalt
                .fromServiceIdentifierAndUsername("service.fjellsoftware.com", "dave.doe@mail.com");

        assert serviceJohn1.equals(serviceJohn2);
        assert !serviceJohn1.equals(otherServiceJohn);
        assert !serviceJohn1.equals(serviceDave);

        // Checks salt is valid
        String password = "password";
        BCrypt.hashpw(password, serviceJohn1);
        BCrypt.hashpw(password, serviceJohn2);
        BCrypt.hashpw(password, otherServiceJohn);
        BCrypt.hashpw(password, serviceDave);
    }

}
