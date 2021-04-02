# User API - Investio

Run a dev server
```bash
$ go run main.go
```

To build a docker image
```bash
$ docker build . -t dewkul/inv-u-api
$ docker tag dewkul/inv-u-api dewkul/inv-u-api:[version]
$ docker push dewkul/inv-u-api:[version]
```