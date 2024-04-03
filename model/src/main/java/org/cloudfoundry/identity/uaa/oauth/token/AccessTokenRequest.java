package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.springframework.util.MultiValueMap;

import java.util.List;
import java.util.Map;

public interface AccessTokenRequest extends MultiValueMap<String, String> {

	OAuth2AccessToken getExistingToken();

	void setExistingToken(OAuth2AccessToken existingToken);

	void setAuthorizationCode(String code);

	String getAuthorizationCode();

	void setCurrentUri(String uri);

	String getCurrentUri();

	void setStateKey(String state);

	String getStateKey();

	void setPreservedState(Object state);

	Object getPreservedState();

	boolean isError();

	void setCookie(String cookie);

	String getCookie();
	
	void setHeaders(Map<? extends String, ? extends List<String>> headers);

	Map<? extends String, ? extends List<String>> getHeaders();

}