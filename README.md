# Ortelius v11 ComponentVersion Microservice

> Version 11.0.0

RestAPI for the ComponentVersion Object
![Release](https://img.shields.io/github/v/release/ortelius/scec-compver?sort=semver)
![license](https://img.shields.io/github/license/ortelius/scec-compver)

![Build](https://img.shields.io/github/actions/workflow/status/ortelius/scec-compver/build-push-chart.yml)
[![MegaLinter](https://github.com/ortelius/scec-compver/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/scec-compver/actions?query=workflow%3AMegaLinter+branch%3Amain)
![CodeQL](https://github.com/ortelius/scec-compver/workflows/CodeQL/badge.svg)
[![OpenSSF-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/scec-compver/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/scec-compver)

![Discord](https://img.shields.io/discord/722468819091849316)

## Path Table

| Method | Path | Description |
| --- | --- | --- |
| GET | [/msapi/compver](#getmsapicompver) | Get a List of Component Versions |
| POST | [/msapi/compver](#postmsapicompver) | Create a ComponentVersion |
| GET | [/msapi/compver/:key](#getmsapicompverkey) | Get a Component Version |

## Reference Table

| Name | Path | Description |
| --- | --- | --- |

## Path Details

***

### [GET]/msapi/compver

- Summary  
Get a List of Component Versions

- Description  
Get a list of component versions for the user.

#### Responses

- 200 OK

***

### [POST]/msapi/compver

- Summary  
Create a ComponentVersion

- Description  
Create a new ComponentVersion and persist it

#### Responses

- 200 OK

***

### [GET]/msapi/compver/:key

- Summary  
Get a Component Version

- Description  
Get a compver details based on the _key or name.

#### Responses

- 200 OK

## References
