# Ortelius v11 CompVer Microservice
RestAPI for the CompVer Object

## Version: 11.0.0

### Terms of service
<http://swagger.io/terms/>

**Contact information:**
Ortelius Google Group
ortelius-dev@googlegroups.com

**License:** [Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0.html)

---
### /msapi/compver

#### GET
##### Summary

Get a List of Component Versions

##### Description

Get a list of component versions for the user.

##### Responses

| Code | Description |
|------|-------------|
| 200  | OK          |

#### POST
##### Summary

Create a CompVer

##### Description

Create a new CompVer and persist it

##### Responses

| Code | Description |
|------|-------------|
| 200  | OK          |

### /msapi/compver/:key

#### GET
##### Summary

Get a Component Version

##### Description

Get a compver details based on the _key or name.

##### Responses

| Code | Description |
|------|-------------|
| 200  | OK          |
