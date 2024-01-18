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

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.io.IOException;
import java.net.URI;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * 飞书做为Keycloak IDP 身份提供商，在流程操作上有些麻烦，具体参考
 * https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/authen-v1/login-overview
 * 1. 获取 授权code
 * 2. 根据 应用appId，App Secret (就是clientId和clientSecret) 获取 app_access_token
 * 3. 根据 授权code 和 app_access_token 获取 user_access_token
 * 4. 根据user_access_token获取用户信息
 * 相对去其他IDP身份提供商，多了一个步骤2, 这里可以覆盖父类中方法
 * 1）自定义类FeishuEndpoint，继承父类中Endpoint，覆盖方法generateTokenRequest，在这个方法中 步骤2，3
 * 2）覆盖父类方法callback，注入FeishuEndpoint
 */
public class FeishuIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig> implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

    //OAuth2使用
    public static final String FEISHU_LOGIN_URL = "https://open.feishu.cn/open-apis/authen/v1/authorize";
    public static final String APP_TOKEN_URL = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal";
    public static final String TOKEN_URL = "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token";
    public static final String PROFILE_URL = "https://open.feishu.cn/open-apis/authen/v1/user_info";

    // 用于获取用户详情 一定要在末尾加 '/'
    public static final String USER_DETAIL_URL = "https://open.feishu.cn/open-apis/contact/v3/users/";
    public static final String DEPARTMENT_NAME_URL = "https://open.feishu.cn/open-apis/contact/v3/departments/";

    public static final String FEISHU_APP_ID_PARAM = "app_id";

    private static final Cache<String, String> feishuCache = CacheBuilder.newBuilder()
            .expireAfterWrite(5600, TimeUnit.SECONDS).build();
    private static final String feishuAppAccessToken = "feishuAppAccessToken";

    public static final String FEISHU_PROFILE_MOBILE = "mobile";
    public static final String FEISHU_PROFILE_NAME = "name";
    public static final String FEISHU_PROFILE_UNION_ID = "union_id";
    public static final String FEISHU_PROFILE_EN_NAME = "en_name";
    public static final String FEISHU_PROFILE_EMAIL = "email";
    private static final String FEISHU_PROFILE_NICKNAME = "nickname";

    public static final String FEISHU_PROFILE_COUNTRY = "country";
    public static final String FEISHU_PROFILE_WORK_STATION = "work_station";
    public static final String FEISHU_PROFILE_GENDER = "gender";
    public static final String FEISHU_PROFILE_CITY = "city";
    public static final String FEISHU_PROFILE_EMPLOYEE_NO = "employee_no";
    public static final String FEISHU_PROFILE_JOIN_TIME = "join_time";
    public static final String FEISHU_PROFILE_ENTERPRISE_EMAIL = "enterprise_email";
    public static final String FEISHU_PROFILE_EMPLOYEE_TYPE = "employee_type";
    public static final String FEISHU_PROFILE_IS_TENANT_MANAGER = "is_tenant_manager";
    public static final String FEISHU_PROFILE_JOB_TITLE = "job_title";

    public static final String FEISHU_PROFILE_DEPARTMENT_IDS = "department_ids";

    public static final String FEISHU_PROFILE_STATUS = "status";
    public static final String FEISHU_PROFILE_IS_FROZEN = "is_frozen";
    public static final String FEISHU_PROFILE_IS_ACTIVATED = "is_activated";
    public static final String FEISHU_PROFILE_IS_RESIGNED = "is_resigned";
    public static final String FEISHU_PROFILE_IS_UNJOIN = "is_unjoin";
    public static final String FEISHU_PROFILE_IS_EXITED = "is_exited";


    public FeishuIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        //config.setAuthorizationUrl(authUrl);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
        //config.getConfig().put(EMAIL_URL_KEY, emailUrl);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    /**
     * BrokeredIdentityContext 为分装在 Keycloak 中的用户信息 <br />
     * BrokeredIdentityContext 会提供默认的几个属性 <br />
     * 可以通过 {@link org.keycloak.broker.provider.BrokeredIdentityContext#setUserAttribute(String, String)} 方法来提供其他的属性
     * <p>
     * <p>
     * 官方链接 (含有字段的详细信息及解释)
     * https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/contact-v3/user/get
     *
     * @param event   当前事件
     * @param profile 存储在 JsonNode 中的用户信息
     * @return 分装到 Keycloak 中的用户信息
     * @see org.keycloak.broker.provider.BrokeredIdentityContext
     */
    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        logger.debug("Received json Profile : " + profile);
        String unionID = getJsonProperty(profile, FEISHU_PROFILE_UNION_ID);
        BrokeredIdentityContext user = new BrokeredIdentityContext(unionID);


        String email = getJsonProperty(profile, FEISHU_PROFILE_ENTERPRISE_EMAIL,
                getJsonProperty(profile, FEISHU_PROFILE_EMAIL, unionID + "@mail.dafault"));

        // 基础属性，必填, 用户名字 取email中，避免中文冲突
        user.setUsername(email.split("@")[0]);
        user.setEmail(email);
        user.setFirstName(getJsonProperty(profile, FEISHU_PROFILE_NICKNAME, getJsonProperty(profile, FEISHU_PROFILE_NAME)));
        user.setLastName(getJsonProperty(profile, FEISHU_PROFILE_EN_NAME, getJsonProperty(profile, FEISHU_PROFILE_NAME)));

        // 额外属性
        // 手机
        user.setUserAttribute(FEISHU_PROFILE_MOBILE, getJsonProperty(profile, FEISHU_PROFILE_MOBILE));

        // 国家
        user.setUserAttribute(FEISHU_PROFILE_COUNTRY, getJsonProperty(profile, FEISHU_PROFILE_COUNTRY));

        // 工作地
        user.setUserAttribute(FEISHU_PROFILE_WORK_STATION, getJsonProperty(profile, FEISHU_PROFILE_WORK_STATION));

        // 性别 0 为保密， 1 为男， 2 为女
        user.setUserAttribute(FEISHU_PROFILE_GENDER, getJsonProperty(profile, FEISHU_PROFILE_GENDER));

        // 城市
        user.setUserAttribute(FEISHU_PROFILE_CITY, getJsonProperty(profile, FEISHU_PROFILE_CITY));

        // 员工工号
        user.setUserAttribute(FEISHU_PROFILE_EMPLOYEE_NO, getJsonProperty(profile, FEISHU_PROFILE_EMPLOYEE_NO));

        // 员工类型
        user.setUserAttribute(FEISHU_PROFILE_EMPLOYEE_TYPE, getJsonProperty(profile, FEISHU_PROFILE_EMPLOYEE_TYPE));

        // 入职时间
        Date date = new Date(profile.get(FEISHU_PROFILE_JOIN_TIME).asLong() * 1000);
        String dateStr = formatDate(date);
        user.setUserAttribute(FEISHU_PROFILE_JOIN_TIME, dateStr);

        // 是否为超级管理员
        user.setUserAttribute(FEISHU_PROFILE_IS_TENANT_MANAGER, getJsonProperty(profile, FEISHU_PROFILE_IS_TENANT_MANAGER));

        // 职务
        user.setUserAttribute(FEISHU_PROFILE_JOB_TITLE, getJsonProperty(profile, FEISHU_PROFILE_JOB_TITLE));

        // 所属部门
        StringBuilder departStr = new StringBuilder();
        if (profile.get(FEISHU_PROFILE_DEPARTMENT_IDS).isArray()) {
            for (JsonNode id : profile.get(FEISHU_PROFILE_DEPARTMENT_IDS)) {
                departStr.append(getDepartmentName(id.asText())).append(",");
            }
            if (departStr.length() > 1) {
                departStr.deleteCharAt(departStr.length() - 1);
            }
        }
        user.setUserAttribute(FEISHU_PROFILE_DEPARTMENT_IDS, departStr.toString());


        // 状态
        user.setUserAttribute(FEISHU_PROFILE_IS_FROZEN, getJsonProperty(profile.get(FEISHU_PROFILE_STATUS), FEISHU_PROFILE_IS_FROZEN));
        user.setUserAttribute(FEISHU_PROFILE_IS_ACTIVATED, getJsonProperty(profile.get(FEISHU_PROFILE_STATUS), FEISHU_PROFILE_IS_ACTIVATED));
        user.setUserAttribute(FEISHU_PROFILE_IS_RESIGNED, getJsonProperty(profile.get(FEISHU_PROFILE_STATUS), FEISHU_PROFILE_IS_RESIGNED));
        user.setUserAttribute(FEISHU_PROFILE_IS_UNJOIN, getJsonProperty(profile.get(FEISHU_PROFILE_STATUS), FEISHU_PROFILE_IS_UNJOIN));
        user.setUserAttribute(FEISHU_PROFILE_IS_EXITED, getJsonProperty(profile.get(FEISHU_PROFILE_STATUS), FEISHU_PROFILE_IS_EXITED));

        user.setIdpConfig(getConfig());
        user.setIdp(this);
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
        return user;
    }

    /**
     * 获取用户信息
     */
    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String userAccessToken) {
        try {
            //获取用户信息profile
            JsonNode profile = SimpleHttp.doGet(PROFILE_URL, session).auth(userAccessToken).asJson();
            if (profile.has("error") && !profile.get("error").isNull()) {
                throw new IdentityBrokerException("Error in Microsoft Graph API response. Payload: " + profile.toString());
            }
            String userId = profile.get("data").get("user_id").asText();

            //获取用户详情
            JsonNode userDetail = getUserDetailByAppAccessTokenAndUserId(getAppAccessToken(), userId);
            return extractIdentityFromProfile(null, userDetail);
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from Feishu", e);
        }
    }
    /**
     * 官方链接 : https://open.feishu.cn/document/ukTMukTMukTM/ukDNz4SO0MjL5QzM/auth-v3/auth/tenant_access_token_internal
     *
     * @return 当前配置下 AppID 对应的 access token
     */
    private String getAppAccessToken() throws Exception {
        String appId = getConfig().getClientId();
        if (!isBlank(feishuCache.getIfPresent(feishuAppAccessToken + appId))) {
            return feishuCache.getIfPresent(feishuAppAccessToken + appId);
        }
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("app_id", appId);
        requestBody.put("app_secret", getConfig().getClientSecret());
        JsonNode responseJson = SimpleHttp.doPost(APP_TOKEN_URL, session)
                .header("Content-Type", "application/json; charset=utf-8")
                .json(requestBody).asJson();
        if (responseJson.get("code").asInt(-1) != 0) {
            logger.warn("Can't get app access token , response :" + responseJson);
            throw new Exception("Can't get app access token");
        }
        String token = getJsonProperty(responseJson, "tenant_access_token");
        feishuCache.put(feishuAppAccessToken + appId, token);
        return token;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new FeishuEndpoint(callback, realm, event, this);
    }

    @Override
    protected String extractTokenFromResponse(String response, String tokenName) {
        if(response == null)
            return null;

        //飞书返回access token 包裹在data节点中
        if (response.startsWith("{")) {
            try {
                JsonNode node = mapper.readTree(response);
                JsonNode dataNode = node.get("data");
                if (dataNode != null) {
                    node = dataNode;
                }
                if(node.has(tokenName)){
                    String s = node.get(tokenName).textValue();
                    if(s == null || s.trim().isEmpty())
                        return null;
                    return s;
                } else {
                    if (node.has("data")) {

                    }
                }
            } catch (IOException e) {
                throw new IdentityBrokerException("Could not extract token [" + tokenName + "] from response [" + response + "] due: " + e.getMessage(), e);
            }
        } else {
            Matcher matcher = Pattern.compile(tokenName + "=([^&]+)").matcher(response);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        return null;
    }

    protected static class FeishuEndpoint extends Endpoint {
        private FeishuIdentityProvider feishuIdentityProvider;
        public FeishuEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event,
                FeishuIdentityProvider provider) {
            super(callback, realm, event, provider);
            this.feishuIdentityProvider = provider;
        }

        /**
         * 基于授权码 + app_access_token 获取用户的详细信息
         * 官方链接 : https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/authen-v1/authen/access_token
         *
         * @param authorizationCode SNS 授权码
         * @return 存储在 Keycloak 中详细的用户信息
         */
        @Override
        public SimpleHttp generateTokenRequest(String authorizationCode) {
            try {
                String appToken = feishuIdentityProvider.getAppAccessToken(); //获取 app access token
                //构造 获取user access token 请求
                Map<String, String> requestBody = new HashMap<>();
                requestBody.put(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
                requestBody.put(OAUTH2_PARAMETER_CODE, authorizationCode);
                logger.info("code exchange access_token, code:" + authorizationCode + ", appToken: " + appToken);
                return SimpleHttp.doPost(TOKEN_URL, session)
                        .header("Authorization", "Bearer " + appToken)
                        .header("Content-Type", "application/json; charset=utf-8")
                        .json(requestBody);
            } catch (Exception e) {
                throw new IdentityBrokerException("Could not obtain user profile from feishu." + e.getMessage(), e);
            }
        }
    }
    /**
     * 官方支持多种查询方式
     * Token 可以采用用户的 user_access_token
     * 用户 ID 方面也可以采用 open_id, union_id
     * 选一种作为认证方案即可
     * <p>
     * 官方链接 : https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/contact-v3/user/get
     *
     * @param appAccessToken 应用的accessToken
     * @param userId          用户 ID
     * @return 含有用户详细信息的 JsonNode
     */
    private JsonNode getUserDetailByAppAccessTokenAndUserId(String appAccessToken, String userId) throws Exception {
        String userDetailWithUserIdUrl = USER_DETAIL_URL + userId;
        JsonNode responseJson = SimpleHttp.doGet(userDetailWithUserIdUrl, session)
                .header("Authorization", "Bearer " + appAccessToken)
                .param("user_id_type", "user_id")
                .asJson();
        if (responseJson.get("code").asInt(-1) != 0) {
            logger.warn("Can't get user detail info , response :" + responseJson);
            logger.info("access token :" + appAccessToken + " userId : " + userId);
            throw new Exception("Can't get user detail info");
        }
        return responseJson.get("data").get("user");
    }


    /**
     * 官方链接 : https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/contact-v3/department/get
     *
     * @param departmentId 部门 ID
     * @return 部门 ID 对应的名称
     */
    private String getDepartmentName(String departmentId) {
        try {
            String userDetailWithUserIdUrl = DEPARTMENT_NAME_URL + departmentId;
            JsonNode responseJson = SimpleHttp.doGet(userDetailWithUserIdUrl, session)
                    .header("Authorization", "Bearer " + getAppAccessToken())
                    //.param("department_id_type", "department_id")
                    .asJson();
            if (responseJson.get("code").asInt(-1) != 0) {
                logger.warn("Can't get department name , response :" + responseJson);
                return "";
            }
            return responseJson.get("data").get("department").get("name").asText();
        } catch (Exception ignore) {
            return "";
        }
    }

    /**
     * 用于登陆请求的跳转，因为为外部跳转
     * 所以需要调用 Response.seeOther 方法
     *
     * @param request 验证请求
     * @return 302 跳转的 response
     */
    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            URI authorizationUrl = createAuthorizationUrl(request).build();
            logger.info("auth url " + authorizationUrl.toString());
            return Response.seeOther(authorizationUrl).build();
        } catch (Exception e) {
            e.printStackTrace(System.out);
            throw new IdentityBrokerException("Could not create authentication request. ", e);
        }
    }


    /**
     * 创建用户跳转到的登陆地址
     * 官方链接：https://open.feishu.cn/document/ukTMukTMukTM/ukzN4UjL5cDO14SO3gTN
     *
     * @param request 登陆请求
     * @return 登陆跳转地址
     */
    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        return UriBuilder.fromUri(FEISHU_LOGIN_URL)
                .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                .queryParam(FEISHU_APP_ID_PARAM, getConfig().getClientId())
                .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());
    }


    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, BrokeredIdentityContext context) {
        user.setUsername(context.getUsername());
        user.setEmail(context.getEmail());
        user.setFirstName(context.getFirstName());
        user.setLastName(context.getLastName());

        // 手机
        user.setSingleAttribute(FEISHU_PROFILE_MOBILE, context.getUserAttribute(FEISHU_PROFILE_MOBILE));
        user.setSingleAttribute(FEISHU_PROFILE_COUNTRY, context.getUserAttribute(FEISHU_PROFILE_COUNTRY));
        user.setSingleAttribute(FEISHU_PROFILE_WORK_STATION, context.getUserAttribute(FEISHU_PROFILE_WORK_STATION));
        user.setSingleAttribute(FEISHU_PROFILE_GENDER, context.getUserAttribute(FEISHU_PROFILE_GENDER));
        user.setSingleAttribute(FEISHU_PROFILE_CITY, context.getUserAttribute(FEISHU_PROFILE_CITY));
        user.setSingleAttribute(FEISHU_PROFILE_EMPLOYEE_NO, context.getUserAttribute(FEISHU_PROFILE_EMPLOYEE_NO));
        user.setSingleAttribute(FEISHU_PROFILE_EMPLOYEE_TYPE, context.getUserAttribute(FEISHU_PROFILE_EMPLOYEE_TYPE));
        user.setSingleAttribute(FEISHU_PROFILE_JOIN_TIME, context.getUserAttribute(FEISHU_PROFILE_JOIN_TIME));
        user.setSingleAttribute(FEISHU_PROFILE_IS_TENANT_MANAGER, context.getUserAttribute(FEISHU_PROFILE_IS_TENANT_MANAGER));
        user.setSingleAttribute(FEISHU_PROFILE_JOB_TITLE, context.getUserAttribute(FEISHU_PROFILE_JOB_TITLE));
        user.setSingleAttribute(FEISHU_PROFILE_DEPARTMENT_IDS, context.getUserAttribute(FEISHU_PROFILE_DEPARTMENT_IDS));
        user.setSingleAttribute(FEISHU_PROFILE_IS_FROZEN, context.getUserAttribute(FEISHU_PROFILE_IS_FROZEN));
        user.setSingleAttribute(FEISHU_PROFILE_IS_ACTIVATED, context.getUserAttribute(FEISHU_PROFILE_IS_ACTIVATED));
        user.setSingleAttribute(FEISHU_PROFILE_IS_RESIGNED, context.getUserAttribute(FEISHU_PROFILE_IS_RESIGNED));
        user.setSingleAttribute(FEISHU_PROFILE_IS_UNJOIN, context.getUserAttribute(FEISHU_PROFILE_IS_UNJOIN));
        user.setSingleAttribute(FEISHU_PROFILE_IS_EXITED, context.getUserAttribute(FEISHU_PROFILE_IS_EXITED));

    }


    /**
     * 飞书身份认证中未用到 scope 属性
     *
     * @return default scope
     */
    @Override
    protected String getDefaultScopes() {
        return "default scope";
    }


    @Override
    public String getJsonProperty(JsonNode jsonNode, String name) {
        if (jsonNode != null && jsonNode.has(name) && !jsonNode.get(name).isNull()) {
            String s = jsonNode.get(name).asText();
            if (s != null && !s.isEmpty())
                return s;
            else
                return "";
        }
        return "";
    }


    public String getJsonListProperty(JsonNode jsonNode, String fieldName) {
        if (!jsonNode.isArray()) {
            return getJsonProperty(jsonNode, fieldName);
        }
        StringBuilder sb = new StringBuilder();
        for (JsonNode node : jsonNode) {
            sb.append(getJsonProperty(node, fieldName)).append(",");
        }
        if (sb.length() >= 1) {
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.toString();
    }

    public String getJsonProperty(JsonNode jsonNode, String name, String defaultValue) {
        if (jsonNode != null && jsonNode.has(name) && !jsonNode.get(name).isNull()) {
            String s = jsonNode.get(name).asText();
            if (s != null && !s.isEmpty())
                return s;
            else
                return defaultValue;
        }

        return defaultValue;
    }

    public static boolean isBlank(String s) {
        if (s == null || s.length() < 1) {
            return true;
        }
        for (char c : s.toCharArray()) {
            if (c != ' ') {
                return false;
            }
        }
        return true;
    }

    private final static SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public static String formatDate(Date date) {
        return format.format(date);
    }
}
