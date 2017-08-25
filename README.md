# shiro
shiro学习笔记

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

