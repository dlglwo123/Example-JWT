package com.jwt.JWT;

import com.jwt.JWT.auth.JwtTokenizer;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.io.Decoders;
import org.junit.jupiter.api.*;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.spi.CalendarNameProvider;

import static org.hamcrest.MatcherAssert.*;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;


@TestInstance(TestInstance.Lifecycle.PER_CLASS) // 메소드 혹은 클래스까리 영향을 주는 테스트 케이스를 테스트 하기 위해
public class JwtTokenizerTest {

    private static JwtTokenizer jwtTokenizer;

    private String secretKey;

    private String base64EncodedSecretKey;

    @BeforeAll
    public void init(){
        jwtTokenizer = new JwtTokenizer();
        secretKey = "kevin1234123412341234123412341234";
        base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(secretKey);
    }

    @Test
    public void encodeBase64SecretKeyTest(){
        System.out.println(base64EncodedSecretKey);

        assertThat(secretKey, is(new String(Decoders.BASE64.decode(base64EncodedSecretKey))));
    }

    @DisplayName("does not throw any Exception when jws verify")
    @Test
    public void verifySignatureTest() {
        String accessToken = getAccessToken(Calendar.MINUTE, 10);
        assertDoesNotThrow(() -> jwtTokenizer.verifySignature(accessToken, base64EncodedSecretKey));
    }

    @Test
    public void verifyExpirationTest() throws InterruptedException{
        String accessToken = getAccessToken(Calendar.SECOND,1);
        assertDoesNotThrow(() -> jwtTokenizer.verifySignature(accessToken, base64EncodedSecretKey));

        TimeUnit.MILLISECONDS.sleep(1500);
        assertThrows(ExpiredJwtException.class,() -> jwtTokenizer.verifySignature(accessToken,base64EncodedSecretKey));
    }




    @Test
    public void generateAccessTokenTest(){
        Map<String,Object> claims = new HashMap<>(); // 인증된 사용자 정보

        claims.put("memberId",1L);
        claims.put("roles", List.of("USER"));

        String subject = "test access token";
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, 10);
        Date expiration = calendar.getTime();

        String accessToken = jwtTokenizer.generateAccessToken(claims,subject,expiration,base64EncodedSecretKey);

        System.out.println(accessToken);

        assertThat(accessToken,notNullValue());
    }

    @Test
    public void generateRefreshToken(){
        String subject = "generateRefreshToken";

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR,24);
        Date expiration = calendar.getTime();

        String refreshToken = jwtTokenizer.generateRefreshToken(subject,expiration,base64EncodedSecretKey);

        System.out.println(refreshToken);

        assertThat(refreshToken,notNullValue());
    }



    private String getAccessToken(int timeUnit, int timeAmount) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("memberId", 1);
        claims.put("roles", List.of("USER"));

        String subject = "test access token";
        Calendar calendar = Calendar.getInstance();
        calendar.add(timeUnit, timeAmount);
        Date expiration = calendar.getTime();
        String accessToken = jwtTokenizer.generateAccessToken(claims, subject, expiration, base64EncodedSecretKey);

        return accessToken;
    }


}
