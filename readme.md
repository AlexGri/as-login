# DatabaseCertHashLoginModule

Кастомный jboss логин модуль.
Использует фингерпринт (sha1 хэш) предоставленного пользователем сертификата как параметр
для поиска имени Principal` a. затем использует это имя как параметр для запроса поска ролей.
Это немного модифицированный копипаст {@link DatabaseCertLoginModule} и {@link DatabaseServerLoginModule}.

## Настройка

параметры:

* securityDomain - имя securityDomain, содержащего jsse конфигурацию хранилища доверенных сертификатов
* verifier - Имя класса для проверки сертификатов
* dsJndiName - JNDI имя datasource, которое будет использоваться для выполнения запросов на полцчение списка пользователей и ролей
* suspendResume - должны ли существующие JTA транзакции быть приостановлены на время выполнения операций с БД.
* principalsQuery - SQL запрос для выборки имени principal. Принимает в качестве параметра fingerprint сертификата.
* rolesQuery - SQL запрос для выборки ролей. Принимает в качестве параметра имя principal.

## Подключение в jboss

Необходимо в jboss-as-7.1.2.Final/modules/certhashmodule/main поместить as-login-1.0-SNAPSHOT.jar и module.xml следующего содержания:
```xml
<module xmlns="urn:jboss:module:1.1" name="certhashmodule">
    <resources>
        <resource-root path="as-login-1.0-SNAPSHOT.jar"/>
    </resources>    
    <dependencies>
        <module name="org.picketbox"/>
        <module name="org.jboss.logging"/>
        <module name="javax.transaction.api"/>
        <module name="javax.api"/>
        <module name="org.apache.commons.codec"/>
    </dependencies>    
</module>
```

после этого можно использовать логин модуль в standalone.xml

```xml
<security-domain name="trust-domain" cache-type="default">
	<jsse keystore-password="password" keystore-url="${ssl.server.keystore}" truststore-password="password" truststore-url="${ssl.server.ca}" client-auth="true"/>
</security-domain>
<security-domain name="internalWS" cache-type="default">
	<authentication>
		<login-module code="org.comsoft.jboss.login.DatabaseCertHashLoginModule" flag="required" module="certhashmodule">
			<module-option name="securityDomain" value="trust-domain"/>
			<module-option name="verifier" value="org.jboss.security.auth.certs.AnyCertVerifier"/>
			<module-option name="dsJndiName" value="java:jboss/datasources/mednetDS"/>
			<module-option name="principalsQuery" value="SELECT u.USER_LOGIN FROM OC_SECURITY_USER u WHERE u.id = 1 and ? is not null"/>
			<module-option name="rolesQuery" value="SELECT 'MY_CUSTOM_ROLE', 'Roles' FROM RDB$DATABASE ur where ? is not null"/>
		</login-module>
	</authentication>
</security-domain>
```

