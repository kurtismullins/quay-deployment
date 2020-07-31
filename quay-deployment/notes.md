## Known Issues

The following issues are known to require extra steps in order to successfully deploy Quay 3.3.

### User Requirement

With Quay 3.3, a User must exist in the database before the Quay instance can be launched. The
following SQL query can be executed to create the user `admin/password`

```
INSERT INTO user (username, email, password_hash, verified)
VALUES ("admin", "example@example.com", "$2a$12$6fF7zCSqHB6y02/bpJjBseUCLwKgeBiwGDz0pOUYqWcpe9/przC9m", 1);
```

The query can also be remotely executed using the following command:

```
oc exec -it mysql56-84fdcb86bf-568mn /opt/rh/rh-mysql56/root/usr/bin/mysql -- \
    --user=root quay -e 'INSERT INTO user (username, email, password_hash, verified) VALUES \
    ("admin", "example@example.com", "$2a$12$6fF7zCSqHB6y02/bpJjBseUCLwKgeBiwGDz0pOUYqWcpe9/przC9m", 1)'
```

# Certificate Requirement

Quay requires a valid certificate to be stored in the `secret`. The files should be named
accordingly: `ssl.cert` and `ssl.key`. They can be generated using the following command:

```
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ssl.key -out ssl.crt
```