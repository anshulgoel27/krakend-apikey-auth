# krakend-apikey-auth
HTTP Basic authentication middleware for the [KrakenD-CE](https://github.com/krakend/krakend-ce.git)

## Install and test
```bash
git clone https://github.com/krakend/krakend-ce.git
cd krakend-ce

#Modify handler_factory.go
#Add to imports: basicauth "github.com/anshulgoel27/krakend-apikey-auth/gin"
#Add to NewHandlerFactory (before "return handlerFactory"): handlerFactory = basicauth.New(handlerFactory, logger)

go get github.com/anshulgoel27/krakend-apikey-auth/gin

make build

./krakend run -c ./krakend.json -d

curl -H'Authorization: Bearer 58427514-be32-0b52-b7c6-d01fada30497' http://localhost:8080/adminonly/test
```

## Example krakend.json
```json
{
    "version": 3,
    "name": "My lovely gateway",
    "port": 8080,
    "cache_ttl": 3600,
    "timeout": "3s",
    "extra_config": {
        "github_com/anshulgoel27/krakend-apikey-auth": {
            "strategy": "header",
            "identifier": "Authorization",
            "keys": [
                {
                    "@plain": "4d2c61e1-34c4-e96c-9456-15bd983c5019",
                    "key": "a6a6d530a77a28fad2359223759d2d2231b516a31de2c09ad046726610f0fd87",
                    "roles": [
                        "user",
                    ],
                    "@description": "ACME Inc."
                },
                {
                    "@plain": "58427514-be32-0b52-b7c6-d01fada30497",
                    "key": "0d85b6ef02794cbf3fef4506286aaba2d499b1f825a5452d9f3444d50b33b48c",
                    "roles": [
                        "admin"
                    ],
                    "@description": "Administrators Inc."
                }
            ]
        }
    },
    "endpoints": [
        {
            "endpoint": "/adminonly/{user}",
            "method": "GET",
            "headers_to_pass": [
                "Authorization",
                "Content-Type"
            ],
            "backend": [
                {
                    "host": [
                        "https://api.github.com"
                    ],
                    "url_pattern": "/",
                    "whitelist": [
                        "authorizations_url",
                        "code_search_url"
                    ]
                }
            ],
            "extra_config": {
                "github_com/anshulgoel27/krakend-apikey-auth": {
                    "roles": [
                        "admin"
                    ]
                }
            }
        },
        {
            "endpoint": "/both/{user}",
            "method": "GET",
            "headers_to_pass": [
                "Authorization",
                "Content-Type"
            ],
            "backend": [
                {
                    "host": [
                        "https://api.github.com"
                    ],
                    "url_pattern": "/",
                    "whitelist": [
                        "authorizations_url",
                        "code_search_url"
                    ]
                }
            ],
            "extra_config": {
                "github_com/anshulgoel27/krakend-apikey-auth": {
                    "roles": [
                        "admin",
                        "user"
                    ]
                }
            }
        }
    ]
}
```
