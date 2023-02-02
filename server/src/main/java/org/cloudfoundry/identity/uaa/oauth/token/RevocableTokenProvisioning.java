/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.resources.ResourceManager;

import java.util.List;

public interface RevocableTokenProvisioning extends ResourceManager<RevocableToken> {

    int deleteRefreshTokensForClientAndUserId(String clientId, String userId, String zoneId);

    List<RevocableToken> getUserTokens(String userId, String zoneId);

    List<RevocableToken> getUserTokens(String userId, String clientId, String zoneId);

    List<RevocableToken> getClientTokens(String clientId, String zoneId);

    void updateRefreshTokenToAssociateWithNewClientSecret(String updatedTokenString, String clientId, String userId);

    void upsert(String id, RevocableToken t, String zoneId);

    RevocableToken retrieveRefreshTokensForClientAndUserId(String clientId, String userId);

    void createIfNotExists(RevocableToken t, String zoneId);
}
