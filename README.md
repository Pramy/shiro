# shiro
## shiro的web.xml的配置

```xml
<filter>
    <filter-name>shiroFilter</filter-name>
    <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
    <init-param>
        <param-name>targetFilterLifecycle</param-name>
        <param-value>true</param-value>
    </init-param>
</filter>
<filter-mapping>
    <filter-name>shiroFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

**DelegatingFilterProxy**是一个Filter的代理类 

```java
//DelegatingFilterProxy.java 第326行 
protected Filter initDelegate(WebApplicationContext wac) throws ServletException {
  //以web.xml的Filter-name去Spring IOC 容器中寻找Filter 
  Filter delegate = wac.getBean(getTargetBeanName(), Filter.class);
   if (isTargetFilterLifecycle()) {
      delegate.init(getFilterConfig());
   }
   return delegate;
}
```

## Spring IOC 中配置

### 1.ShiroFilterFactoryBean

```xml
<!-- Define the Shiro Filter here (as a FactoryBean) instead of directly in web.xml -
     web.xml uses the DelegatingFilterProxy to access this bean.  This allows us
     to wire things with more control as well utilize nice Spring things such as
     PropertiesPlaceholderConfigurer and abstract beans or anything else we might need: -->
<bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean">
    <property name="securityManager" ref="securityManager"/>
    <property name="loginUrl" value="login.jsp"/>
    <property name="successUrl" value="list.jsp"/>
    <property name="unauthorizedUrl" value="test.jsp"/>
    <!-- The 'filters' property is not necessary since any declared javax.servlet.Filter bean
         defined will be automatically acquired and available via its beanName in chain
         definitions, but you can perform overrides or parent/child consolidated configuration
         here if you like: -->
    <!-- <property name="filters">
        <util:map>
            <entry key="aName" value-ref="someFilterPojo"/>
        </util:map>
    </property> -->
    <property name="filterChainDefinitions">
        <value>
            /login.jsp = anon
            # everything else requires authentication:
            /** = authc
        </value>
```
- value:格式 是 url = 过滤器 （anon：允许匿名访问，anthc：需要登录认证），url匹配方式支持Ant风格?匹配一个字符，*匹配一个或者多个字符，**匹配一个或者多个路径，匹配原则重上到下优先匹配**


## 1.认证流程

- 获取当前的Subject。调用SecurityUtils.getSubject();
- 测试当前用户是否已经被认证，调用Subject的isAuthenticated();
- 若没有被认证，封装UsernamePasswordToken对象，执行登录
- 执行登录：调用Subject 的 login(AuthenticationToken)方法
- 由shiro完成对密码的比对


```java
protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    UsernamePasswordToken passwordToken = (UsernamePasswordToken) token;
    //获取用户名
    String userName = passwordToken.getUsername();
    //从数据库中获取信息
  	String password = ;
    return new SimpleAuthenticationInfo(userName,password,getName());
}
```

## 2.密码比对

1.第一种是继承了`abstract class AuthenticatingRealm` 的realm，在realm初始化的时候会调用抽象类的空构造方法，

```java
//146行
public AuthenticatingRealm() {
        this(null, new SimpleCredentialsMatcher());
    }
```

这时候realm就会持有一个SimpleCredentialsMatcher对象，

等到开始对密码认证的时候，既执行subject.login(token)方法是，会调用到抽象类中的

```java
protected void assertCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) throws AuthenticationException {
  //这里的cm其实是一开始初始化的SimpleCredentialsMatcher
    CredentialsMatcher cm = getCredentialsMatcher();
    if (cm != null) {
        if (!cm.doCredentialsMatch(token, info)) {
            //匹配错误抛异常
            throw new IncorrectCredentialsException(msg);
        }
    } else {
		//如果cm是空就抛异常
    }
}
```

SimpleCredentialsMatcher的doCredentialsMatch方法

```java
public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
  	//获取前端传过来的密码
    Object tokenCredentials = getCredentials(token);
  	//获取数据库中的密码
    Object accountCredentials = getCredentials(info);
  	//进行对比
    return equals(tokenCredentials, accountCredentials);
}
```

## 3.密码MD5 迭代加密

spring配置bean替代原本的SimpleCredentialsMatcher

```xml
<bean id="myRealm" class="com.pramy.realm.MyRealm">
  <!--指定credentialsMatcher为HashedCredentialsMatcher,并且选择加密类型为MD5，迭代次数为1024-->
    <property name="credentialsMatcher">
        <bean class="org.apache.shiro.authc.credential.HashedCredentialsMatcher"
              p:hashAlgorithmName="MD5"
              p:hashIterations="1024"
        />
    </property>
</bean>
```

  在调用`HashedCredentialsMatcher`的`doCredentialsMatch`的时候

```java
public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
  //这里的tokenHashedCredentials是token加密后的字符串
    Object tokenHashedCredentials = hashProvidedCredentials(token, info);
    Object accountCredentials = getCredentials(info);
    return equals(tokenHashedCredentials, accountCredentials);
}
```

hashProvidedCredentials方法中，调用了

```java
protected Hash hashProvidedCredentials(Object credentials, Object salt, int hashIterations) {
    //获取配置的加密算法的名字
  	String hashAlgorithmName = assertHashAlgorithmName();
    //参数分别是：加密算法名字，前端传过来的密码，盐，迭代次数
    return new SimpleHash(hashAlgorithmName, credentials, salt, hashIterations);
}
```

## 4.加盐

用随机字符串或者唯一的字符串作为盐值

```java
ByteSource credentialsSalt = ByteSource.Util.bytes(userName);
new SimpleAuthenticationInfo(principal, hashedCredentials, credentialsSalt, realmName)
```

或者加盐后的密码值

```java
new SimpleHash(hashAlgorithmName, credentials, salt, hashIterations);
```

## 5.多Realm认证和认证策略

首先在spring容器中配置好realm，可以配置默认的CredentialsMatcher，也可以配置HashedCredentialsMatcher

```xml
<bean id="myRealm" class="com.pramy.realm.MyRealm">
    <property name="credentialsMatcher">
        <bean class="org.apache.shiro.authc.credential.HashedCredentialsMatcher"
              p:hashAlgorithmName="MD5"
              p:hashIterations="1024"/>
    </property>
</bean>

<bean id="secondRealm" class="com.pramy.realm.SecondRealm">
    <property name="credentialsMatcher">
        <bean class="org.apache.shiro.authc.credential.HashedCredentialsMatcher"
        p:hashAlgorithmName="SHA1"
        p:hashIterations="1024"/>
    </property>
</bean>
```

配置好之后，需要配置realm

第一个方法：

配置认证器，将realm 注入到认证器中，然后SecurityManager再引用认证器

```xml
    <bean id="securityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">
        <property name="cacheManager" ref="cacheManager"/>
        <!--引用认证器-->
        <property name="authenticator" ref="authenticator"/>
    </bean>
  <!--配置认证器，将realm注入进去-->
    <bean id="authenticator" class="org.apache.shiro.authc.pam.ModularRealmAuthenticator">
        <property name="realms">
            <list>
                <ref bean="myRealm"/>
                <ref bean="secondRealm"/>
            </list>
        </property>
    </bean>
```

第二个方法：

直接在SecurityManager中注入realm（推荐）

```xml
<bean id="securityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">
    <property name="cacheManager" ref="cacheManager"/>
    <property name="realms">
        <list>
            <ref bean="myRealm"/>
            <ref bean="secondRealm"/>
        </list>
    </property>
</bean>
```

因为在初始化SecurityManager的时候会执行

```java
protected void afterRealmsSet() {
    super.afterRealmsSet();
  //判断认证器是否是ModularRealmAuthorizer，如果是话就会把realm设置给ModularRealmAuthorizer
    if (this.authorizer instanceof ModularRealmAuthorizer) {
        ((ModularRealmAuthorizer) this.authorizer).setRealms(getRealms());
    }
}
```

所以ModularRealmAuthorizer也会持有realms

---

如果配置了多Realm认证，需要配置认证策略，默认使用`AtLeastOneSuccessfulStrategy`

```java
protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
    assertRealmsConfigured();
    Collection<Realm> realms = getRealms();
    if (realms.size() == 1) {
        return doSingleRealmAuthentication(realms.iterator().next(), authenticationToken);
    } else {
      //多Realm认证
        return doMultiRealmAuthentication(realms, authenticationToken);
    }
}
```

其中的doMultiRealmAuthentication方法中

```java
protected AuthenticationInfo doMultiRealmAuthentication(Collection<Realm> realms, AuthenticationToken token) {
  //获取认证策略，默认使用AtLeastOneSuccessfulStrategy
    AuthenticationStrategy strategy = getAuthenticationStrategy();
		····中间内容省略
  //返回所有认证成功的信息
    return aggregate;
}
```

- AtLeastOneSuccessfulStrategy：返回所有认证成功的信息，有一个成功就可以
- FirstSuccessfulStrategy：返回第一个认证成功的信息，有一个成功就可以
- AllSuccessfulStrategy：只有所有认证成功后才会返回所有的认证信息

需要在认证器中配置

```xml
<bean id="authenticator" class="org.apache.shiro.authc.pam.ModularRealmAuthenticator">
    <property name="authenticationStrategy">
        <bean class="org.apache.shiro.authc.pam.AllSuccessfulStrategy"/>
    </property>
</bean>
```

## 6.权限分配，角色分配

需要配置权限认证的Realm，需要继承AuthorizingRealm

然后实现两个方法

```java
//认证方法 
protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
//授权方法
protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals)
```

在授权方法中可以从数据库中查询role和permission

```java
Set<String> roles = new HashSet<>();
Set<String> permison = new HashSet<>();
SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
//设置角色
authorizationInfo.setRoles(roles);
//设置权限
authorizationInfo.setStringPermissions(permison);
```

## 7.注解配置

- RequiresAuthentication：对应authc，需要被认证才可以登录
- RequiresGuest：对应anon，可以匿名访问
- RequiresPermissions：对应permission，需要权限认证
- RequiresRoles：对应roles，需要角色认证
- RequiresUser：对应user，需要被认证或者被记住

需要开启spring对注解的支持，由于注解注入式AOP的方式

```xml
<!--重要，需要开启aop的自动代理-->
<aop:aspectj-autoproxy />

<bean  class="org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor">
    <property name="securityManager" ref="securityManager"/>
</bean>
```

但是，如果权限访问有误的话，会抛出UnauthorizedException.Exception，所以我们需要用spring的Exception来捕获异常

```java
@ExceptionHandler({UnauthorizedException.class})
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public ModelAndView processUnauthenticatedException(NativeWebRequest request, UnauthorizedException e) {
  ModelAndView mv = new ModelAndView();
  mv.addObject("exception", e);
  mv.setViewName("unauthorized");
  return mv;
}
```

