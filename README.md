# jwt-demo 

A very simple way of implementing JWT Authentication in a REST API using Go 

### Get the source code
```bash
go get -u github.com/john-deng/jwt-demo
```

### Generate RSA signing files via shell (adjust as needed)
```bash
openssl genrsa -out config/app.rsa 1024
openssl rsa -in config/app.rsa -pubout > config/app.rsa.pub

```

### Run 
```bash
go run main.go
```

### Test

```bash
curl -H """Authorization: Bearer $(curl -d '{"username":"johndeng","password":"p@ssword"}' -H "Content-Type: application/json" -X POST http://localhost:3001/login 2>/dev/null | jq -r '.token')""" http://localhost:3001/ping
```
