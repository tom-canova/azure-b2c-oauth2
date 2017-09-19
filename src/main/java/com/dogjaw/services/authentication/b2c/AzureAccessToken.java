package com.dogjaw.services.authentication.b2c;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.codehaus.jackson.JsonParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.io.IOException;
import java.util.Date;
import java.util.Map;

/**
 * Created by Keith Hoopes on 2/3/2016.
 *
 * Represents an OpenID Token retrieved from Azure.
 * Adds some additional information that azure requires,
 * and some that security requires.
 */
public class AzureAccessToken extends DefaultOAuth2AccessToken{
	private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private Date refreshTokenExpiration;
    private Date notBefore;
    private AzureProfile profile;

    public AzureAccessToken(OAuth2AccessToken accessToken) throws IOException {

        super(accessToken);

        DefaultOAuth2AccessToken token;

        if(accessToken instanceof  DefaultOAuth2AccessToken){

            token = (DefaultOAuth2AccessToken) accessToken;
        }
        else{

            token = new DefaultOAuth2AccessToken(accessToken);
        }
        parseAzureTokenInformation(token);
    }

    private void parseAzureTokenInformation(DefaultOAuth2AccessToken accessToken) throws IOException {

        long now = System.currentTimeMillis();
        Map<String, Object> info = accessToken.getAdditionalInformation();

        if (info != null && info.size() > 0) {

            if (this.getValue() == null) {

                String idToken = (String) info.get("id_token");
                this.setValue(idToken);
            }

            if (this.getExpiration() == null) {

                Integer expiresInStr = (Integer) info.get("id_token_expires_in");

                if (expiresInStr != null) {

                    long seconds = expiresInStr.longValue();
                    long milliSeconds = seconds * 1000;
                    Date expiration = new Date(now + milliSeconds);

                    accessToken.setExpiration(expiration);
                }
            }

            String refreshExpiresInStr = (String) info.get("refresh_token_expires_in");
            if (refreshExpiresInStr != null) {

                long seconds = Long.parseLong(refreshExpiresInStr);
                long milliSeconds = seconds * 1000;
                this.refreshTokenExpiration = new Date(now + milliSeconds);
            }

            Integer notBeforeStr = (Integer) info.get("not_before");
            if (notBeforeStr != null) {

                long seconds = notBeforeStr.longValue();
                long milliSeconds = seconds * 1000;
                this.notBefore = new Date(now + milliSeconds);
            }

            String profile64Encoded = (String) info.get("profile_info");
            byte[] profileBytes = Base64.decode(profile64Encoded.getBytes());
            String profileJson = new String(profileBytes);
            try {
            	logger.info("creating AzureProfile with: "+profileJson);
                this.profile = OBJECT_MAPPER.readValue(profileBytes, AzureProfile.class);
            }
            catch(Exception e){
            	e.printStackTrace();
                this.profile = OBJECT_MAPPER.readValue("{\"ver\":\"1.0\",\"tid\":\"115e4993-c5c5-4143-bd54-d3e7c4e42746\",\"sub\":null,\"name\":\"Tom\",\"preferred_username\":null,\"idp\":null}", AzureProfile.class);
                //this.profile.setAdditionalProperty(name, value);
                //There are times when Azure returns some malformed JSON for the profile_info.
            }
        }
    }

    public Date getRefreshTokenExpiration() {

        return refreshTokenExpiration;
    }

    public AzureProfile getProfile() {

        return profile;
    }

    public Date getNotBefore() {

        return notBefore;
    }
}
