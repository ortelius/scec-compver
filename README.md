# Ortelius v11 ComponentVersion Microservice
RestAPI for the ComponentVersion Object
![Release](https://img.shields.io/github/v/release/ortelius/scec-compver?sort=semver)
![license](https://img.shields.io/github/license/ortelius/scec-compver)

![Build](https://img.shields.io/github/actions/workflow/status/ortelius/scec-compver/build-push-chart.yml)
[![MegaLinter](https://github.com/ortelius/scec-compver/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/scec-compver/actions?query=workflow%3AMegaLinter+branch%3Amain)
![CodeQL](https://github.com/ortelius/scec-compver/workflows/CodeQL/badge.svg)
[![OpenSSF-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/scec-compver/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/scec-compver)

![Discord](https://img.shields.io/discord/722468819091849316)

## Version: 11.0.0

### Terms of service
<http://swagger.io/terms/>

**Contact information:**
Ortelius Google Group
<ortelius-dev@googlegroups.com>

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

Create a ComponentVersion

##### Description

Create a new ComponentVersion and persist it

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
