/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.social.feishu;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * @author Jinxin
 * created at 2022/1/20 10:39
 **/
public class FeishuUserAttributeMapper extends AbstractJsonUserAttributeMapper {

    public static final String PROVIDER_ID = "feishu-user-attribute-mapper";
    private static final String[] cp = new String[]{FeishuIdentityProviderFactory.PROVIDER_ID};

    @Override
    public String[] getCompatibleProviders() {
        return cp;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }


    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        user.setUsername(context.getUsername());
        user.setEmail(context.getEmail());
        user.setFirstName(context.getFirstName());
        user.setLastName(context.getLastName());

        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_MOBILE, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_MOBILE));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_COUNTRY, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_COUNTRY));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_WORK_STATION, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_WORK_STATION));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_GENDER, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_GENDER));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_CITY, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_CITY));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_EMPLOYEE_NO, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_EMPLOYEE_NO));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_EMPLOYEE_TYPE, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_EMPLOYEE_TYPE));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_JOIN_TIME, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_JOIN_TIME));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_IS_TENANT_MANAGER, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_IS_TENANT_MANAGER));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_JOB_TITLE, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_JOB_TITLE));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_DEPARTMENT_IDS, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_DEPARTMENT_IDS));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_IS_FROZEN, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_IS_FROZEN));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_IS_ACTIVATED, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_IS_ACTIVATED));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_IS_RESIGNED, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_IS_RESIGNED));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_IS_UNJOIN, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_IS_UNJOIN));
        user.setSingleAttribute(FeishuIdentityProvider.FEISHU_PROFILE_IS_EXITED, context.getUserAttribute(FeishuIdentityProvider.FEISHU_PROFILE_IS_EXITED));

    }

}
