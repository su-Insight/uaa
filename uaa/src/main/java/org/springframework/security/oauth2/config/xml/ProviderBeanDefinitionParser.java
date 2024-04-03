package org.springframework.security.oauth2.config.xml;

import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

public abstract class ProviderBeanDefinitionParser extends AbstractBeanDefinitionParser {

	@Override
	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

		String tokenServicesRef = element.getAttribute("token-services-ref");
		String serializerRef = element.getAttribute("serialization-service-ref");

		if (!StringUtils.hasText(tokenServicesRef)) {
			tokenServicesRef = "oauth2TokenServices";
			BeanDefinitionBuilder tokenServices = BeanDefinitionBuilder.rootBeanDefinition(DefaultTokenServices.class);
			AbstractBeanDefinition tokenStore = BeanDefinitionBuilder.rootBeanDefinition(InMemoryTokenStore.class).getBeanDefinition();
			tokenServices.addPropertyValue("tokenStore", tokenStore);
			parserContext.getRegistry().registerBeanDefinition(tokenServicesRef, tokenServices.getBeanDefinition());
		}

		return parseEndpointAndReturnFilter(element, parserContext, tokenServicesRef, serializerRef);
	}

	protected abstract AbstractBeanDefinition parseEndpointAndReturnFilter(Element element, ParserContext parserContext,
			String tokenServicesRef, String serializerRef);

}
