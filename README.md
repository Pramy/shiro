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

**DelegatingFilterProxy **是一个Filter的代理类 

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
    </property>
</bean>
```

- value:格式 是 url = 过滤器 （anon：允许匿名访问，anthc：需要登录认证），url匹配方式支持Ant风格?匹配一个字符，*匹配一个或者多个字符，**匹配一个或者多个路径，匹配原则重上到下优先匹配

