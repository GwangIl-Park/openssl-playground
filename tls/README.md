1. rootCA용 rsa키 생성

```jsx
openssl genrsa -out rootCA.key
```

2. rootCA용 CSR 생성

```jsx
openssl req -new -key rootCA.key -out rootCA.csr
```

![image](https://github.com/GwangIl-Park/openssl_playground/assets/40749130/1582f814-f9ac-4a14-93b5-73fc77d62201)

3. rootCA용 인증서 생성

```jsx
openssl x509 -req -in rootCA.csr -signkey rootCA.key -out rootCA.crt -fingerprint -sha256
```

![image](https://github.com/GwangIl-Park/openssl_playground/assets/40749130/1c0d5918-ad70-4d53-bbf2-6fab267d47f9)

4. 서버용 rsa키 생성

```jsx
openssl genrsa -out server.key
```

5. 서버용 CSR 생성

```jsx
openssl req -new -key server.key -out server.csr
```

![image](https://github.com/GwangIl-Park/openssl_playground/assets/40749130/edbc03e3-02cf-4a9d-86b6-c83ca7bb27b9)

6. 서버용 인증서 생성

```jsx
openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out server.crt -fingerprint -sha256
```

![image](https://github.com/GwangIl-Park/openssl_playground/assets/40749130/44c9aa22-9983-4d5d-a886-7334bfbfb20f)

7. 소스 빌드

```
make
```

8. client, server 각각 실행

- server쪽 로그

![image](https://github.com/GwangIl-Park/openssl_playground/assets/40749130/df099394-1187-4d72-8dcd-472763b19b44)

- client쪽 로그

![image](https://github.com/GwangIl-Park/openssl_playground/assets/40749130/57b0289c-7aa9-455d-8792-45a4dc383045)

- 데이터 암호화 확인 (tcpdump로 확인)

```
tcpdump -i lo -w test.pcap
```

![image](https://github.com/GwangIl-Park/openssl_playground/assets/40749130/72103d9f-e059-4cdd-9d65-50b0b3c0a573)
