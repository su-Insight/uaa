package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.http.HttpHeaders;
import org.springframework.util.MultiValueMap;

public interface RequestEnhancer {
		void enhance(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form,
			HttpHeaders headers);
}
