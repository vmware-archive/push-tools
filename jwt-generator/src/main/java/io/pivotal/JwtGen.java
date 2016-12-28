package io.pivotal;

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.Base64URL;
import net.minidev.json.JSONObject;

import javax.xml.bind.DatatypeConverter;
import java.text.ParseException;

public class JwtGen {

    private static String generateValidJWT(final String secret, final String customUserId, final boolean isHex) {
        final JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(
                new JSONObject(ImmutableMap.of("custom_user_id", customUserId))
        ));

        try {
            if (isHex) {
                jwsObject.sign(new MACSigner(DatatypeConverter.parseHexBinary(secret)));
            } else {
                jwsObject.sign(new MACSigner(secret));
            }
        } catch (JOSEException e) {
            System.err.println("Error signing JWT: " + e.getLocalizedMessage());
            System.exit(-1);
        }

        return jwsObject.serialize();
    }

    private static void decodeJWT(final String secret, final String input, final boolean isHex) throws ParseException, JOSEException {
        final JWSObject jwsObject = JWSObject.parse(input);
        final JWSVerifier verifier;

        if (isHex) {
            verifier = new MACVerifier(DatatypeConverter.parseHexBinary(secret));
        } else {
            verifier = new MACVerifier(secret);
        }

        if (jwsObject.verify(verifier)) {
            System.out.println("Token: '" + input + "' is a valid JWT token\n");
        } else {
            System.err.println("Token: '" + input + "' is **NOT A VALID JWT TOKEN**\n");
        }

        final Base64URL[] parts = jwsObject.getParsedParts();
        System.out.println("HEADER:\n\t" + parts[0].decodeToString());
        System.out.println("PAYLOAD:\n\t" + parts[1].decodeToString());
        System.out.println("SIGNATURE:\n\t" + DatatypeConverter.printHexBinary(parts[2].decode()));
    }

    public static void usage() {
        System.out.println("Usage: jwt-gen generate|generatehex|decode|decodehex\t");

        System.out.println("Usage: jwt-gen generate secret custom_user_id");
        System.out.println("\teg: ./jwt-gen generate asev01L5kAa9145zJ5Zg3o08I8OINN8L bond007");
        System.out.println("\tnote: this will require a min 32 byte secret and use HMAC256 only\n");

        System.out.println("Usage: jwt-gen generatehex secretHex custom_user_id");
        System.out.println("\teg: ./jwt-gen generatehex 6173657630314C356B4161393134357A4A355A67336F303849384F494E4E384C bond007");
        System.out.println("\tnote: this will require a min 32 byte secret in hex and use HMAC256 only\n");

        System.out.println("Usage: jwt-gen decode secret custom_user_id");
        System.out.println("\teg: ./jwt-gen decode asev01L5kAa9145zJ5Zg3o08I8OINN8L eyJhbGciOiJIUzI1NiJ9.eyJjdXN0b21fdXNlcl9pZCI6ImJvbmQwMDcifQ.I_ebQ-2NZjzTRWE-nuwgZfGNtz_4m6Bh9TlLFs06GU4\n");

        System.out.println("Usage: jwt-gen decodehex secretHex custom_user_id");
        System.out.println("\teg: ./jwt-gen decodehex decodehex 6173657630314C356B4161393134357A4A355A67336F303849384F494E4E384C eyJhbGciOiJIUzI1NiJ9.eyJjdXN0b21fdXNlcl9pZCI6ImJvbmQwMDcifQ.I_ebQ-2NZjzTRWE-nuwgZfGNtz_4m6Bh9TlLFs06GU4");
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            usage();
            return;
        }

        if (args.length != 3) {
            usage();
            System.err.println("Error: wrong number of arguments");
            System.exit(1);
        }

        if ("generate".equals(args[0])) {
            System.out.println("Generating jwt with secret: '" + args[1] +"' and custom_user_id: '" + args[2] + "'\n");

            final String jwt = generateValidJWT(args[1], args[2], false);

            System.out.println(jwt);
        } else if ("generatehex".equals(args[0])) {
            System.out.println("Generating jwt with secretHex: '" + args[1] + "' and custom_user_id: '" + args[2] + "'\n");

            final String jwt = generateValidJWT(args[1], args[2], true);

            System.out.println(jwt);
        } else if ("decode".equals(args[0])) {
            try {
                decodeJWT(args[1], args[2], false);
            } catch (Exception e) {
                System.err.println(e.getLocalizedMessage());
                System.exit(1);
            }
        } else if ("decodehex".equals(args[0])) {
            try {
                decodeJWT(args[1], args[2], true);
            } catch (Exception e) {
                System.err.println(e.getLocalizedMessage());
                System.exit(1);
            }
        } else {
            System.err.println("Error: wrong number of arguments");
            System.exit(1);
        }

        System.exit(0);
    }
}
