// Ortelius v11 ComponentVersion Microservice that handles creating and retrieving ComponentVersion
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/go-resty/resty/v2"
	_ "github.com/ortelius/scec-compver/docs"
	"github.com/ortelius/scec-compver/models"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
	"github.com/goark/go-cvss/v2/metric"
	metric_v3 "github.com/goark/go-cvss/v3/metric"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/swagger"
	"github.com/ortelius/scec-commons/database"
	"github.com/ortelius/scec-commons/model"
)

var logger = database.InitLogger()
var dbconn = database.InitializeDatabase()

// GetComponentVersions godoc
// @Summary Get a List of Component Versions
// @Description Get a list of component versions for the user.
// @Tags compver
// @Accept */*
// @Produce json
// @Success 200
// @Router /msapi/compver [get]
func GetComponentVersions(c *fiber.Ctx) error {

	var cursor arangodb.Cursor     // db cursor for rows
	var err error                  // for error handling
	var ctx = context.Background() // use default database context

	// query all the compvers in the collection
	aql := `FOR compver in evidence
			FILTER (compver.objtype == 'ComponentVersionDetails')
			RETURN compver`

	// execute the query with no parameters
	if cursor, err = dbconn.Database.Query(ctx, aql, nil); err != nil {
		logger.Sugar().Errorf("Failed to run query: %v", err) // log error
	}

	defer cursor.Close() // close the cursor when returning from this function

	components := model.NewComponents() // define a list of compvers to be returned

	for cursor.HasMore() { // loop thru all of the documents

		compver := model.NewComponentVersion() // fetched compver
		var meta arangodb.DocumentMeta         // data about the fetch

		// fetch a document from the cursor
		if meta, err = cursor.ReadDocument(ctx, compver); err != nil {
			logger.Sugar().Errorf("Failed to read document: %v", err)
		}
		components.Components = append(components.Components, compver)       // add the compver to the list
		logger.Sugar().Infof("Got doc with key '%s' from query\n", meta.Key) // log the key
	}

	return c.JSON(components) // return the list of compvers in JSON format
}

// GetComponentVersionDetails godoc
// @Summary Get a Component Version
// @Description Get a compver details based on the _key or name.
// @Tags compver
// @Accept */*
// @Produce json
// @Success 200
// @Router /msapi/compver/:key [get]
func GetComponentVersionDetails(c *fiber.Ctx) error {

	var cursor arangodb.Cursor     // db cursor for rows
	var err error                  // for error handling
	var ctx = context.Background() // use default database context

	key := c.Params("key")                // key from URL
	parameters := map[string]interface{}{ // parameters
		"key": key,
	}

	// query the compvers that match the key or name
	aql := `FOR comp IN evidence
	FILTER (comp.objtype == 'ComponentVersionDetails' && comp._key == @key)
	RETURN MERGE(comp, {
	"packages": (
		FOR sbom IN sbom
		FILTER sbom.objtype == "SBOM" && comp.sbom_key == sbom._key
		FOR packages IN sbom.content.components
			LET lics = LENGTH(packages.licenses) > 0
			? (FOR lic IN packages.licenses
				FILTER LENGTH(packages.licenses) > 0
					LET id = LENGTH(lic.license.id) > 0
					? lic.license.id
					: SPLIT(lic.license.name, "----")[0]
					RETURN id
				)
			: [""]

			FOR lic IN lics
				RETURN {
				"name": packages.name,
				"version": packages.version,
				"purl": packages.purl,
				"license": lic,
				"language": SPLIT(SPLIT(packages.purl, ":")[1], "/")[0]
				}
		)
		}
	)`

	// run the query with patameters
	if cursor, err = dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters}); err != nil {
		logger.Sugar().Errorf("Failed to run query: %v", err)
	}

	defer cursor.Close() // close the cursor when returning from this function

	compver := model.NewComponentVersionDetails() // define a compver to be returned

	if cursor.HasMore() { // compver found
		var meta arangodb.DocumentMeta // data about the fetch

		if meta, err = cursor.ReadDocument(ctx, compver); err != nil { // fetch the document into the object
			logger.Sugar().Errorf("Failed to read document: %v", err)
		}
		logger.Sugar().Infof("Got doc with key '%s' from query\n", meta.Key)

	} else { // not found so get from NFT Storage
		if jsonStr, exists := database.MakeJSON(key); exists {
			if err := json.Unmarshal([]byte(jsonStr), compver); err != nil { // convert the JSON string from LTF into the object
				logger.Sugar().Errorf("Failed to unmarshal from LTS: %v", err)
			}
		}
	}

	for _, pkg := range compver.Packages {
		pkgInfo, _ := models.PURLToPackage(pkg.Purl)

		osvPkg := models.PackageDetails{
			Name:      pkgInfo.Name,
			Version:   pkgInfo.Version,
			Commit:    pkgInfo.Commit,
			Ecosystem: models.Ecosystem(pkgInfo.Ecosystem),
			CompareAs: models.Ecosystem(pkgInfo.Ecosystem),
		}

		parameters = map[string]interface{}{ // parameters
			"name": pkg.Name,
		}

		aql = `FOR vuln IN vulns
				FOR affected in vuln.affected
					FILTER (@name in vuln.affected[*].package.name AND affected.package.name == @name)
					RETURN merge({ID: vuln._key}, vuln)`

		if len(strings.TrimSpace(pkg.Purl)) > 0 {
			// Split the purl string by "@" and "?"
			parts := strings.Split(pkg.Purl, "@")
			parts = strings.Split(parts[0], "?")

			// The first part before "@" and "?" is in parts[0]
			purl := parts[0]

			parameters = map[string]interface{}{ // parameters
				"name": pkg.Name,
				"purl": purl,
			}

			aql = `FOR vuln IN vulns
					FOR affected in vuln.affected
						FILTER (@name in vuln.affected[*].package.name AND affected.package.name == @name) OR
							(@purl in vuln.affected[*].package.purl AND STARTS_WITH(affected.package.purl,@purl))
						RETURN merge({ID: vuln._key}, vuln)`
		}

		// run the query with patameters
		if cursor, err = dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters}); err != nil {
			logger.Sugar().Errorf("Failed to run query: %v", err)
		}

		score := 0.0
		severity := ""
		defer cursor.Close() // close the cursor when returning from this function

		for cursor.HasMore() { // vuln found

			var vuln models.Vulnerability

			if _, err = cursor.ReadDocument(ctx, &vuln); err != nil { // fetch the document into the object
				logger.Sugar().Errorf("Failed to read document: %v", err)
			}

			if models.IsAffected(vuln, osvPkg) && !strings.Contains(pkg.CVE, vuln.ID) {
				pkg.CVE = strings.TrimLeft(fmt.Sprintf("%s,%s", pkg.CVE, vuln.ID), ",")
				if !strings.Contains(pkg.Summary, vuln.Summary) {
					pkg.Summary = strings.TrimLeft(pkg.Summary+"|"+vuln.Summary, "|")
				}
				if len(vuln.Severity) > 0 {
					if vuln.Severity[0].Type == "CVSS_V3" {
						if bm, err := metric_v3.NewBase().Decode(vuln.Severity[0].Score); err == nil {
							if bm.Score() > score {
								score = bm.Score()
								severity = bm.Severity().String()
							}
						}
					} else {
						if bm, err := metric.NewBase().Decode(vuln.Severity[0].Score); err == nil {
							if bm.Score() > score {
								score = bm.Score()
								severity = bm.Severity().String()
							}
						}
					}
				}
			}
		}

		pkg.Score = score
		pkg.Severity = severity

		if severity == "" {
			pkg.Severity = "None"
		}
	}

	sort.Slice(compver.Packages, func(i, j int) bool {
		a, b := compver.Packages[i], compver.Packages[j]
		return a.Score > b.Score || (a.Score == b.Score && (a.Name < b.Name || (a.Name == b.Name && a.Version < b.Version)))
	})

	return c.JSON(compver) // return the compver in JSON format
}

func convertGitURL(gitURL string) string {
	if strings.HasPrefix(gitURL, "git@") || strings.Contains(gitURL, ":") {
		gitURL = strings.Replace(gitURL, "ssh://", "", 1) // Remove "ssh://" if present
		parts := strings.Split(gitURL, ":")
		if len(parts) == 2 {
			hostname := parts[0]
			repoPath := parts[1]
			hostname = strings.TrimPrefix(hostname, "git@")
			gitURL = hostname + "/" + repoPath
		} else {
			gitURL = strings.Replace(gitURL, ":", "/", 1)
		}
	}
	gitURL = strings.Replace(gitURL, ".git", "", -1)
	return gitURL
}

// NewComponentVersionDetails godoc
// @Summary Create a ComponentVersion
// @Description Create a new ComponentVersion and persist it
// @Tags compver
// @Accept application/json
// @Produce json
// @Success 200
// @Router /msapi/compver [post]
func NewComponentVersionDetails(c *fiber.Ctx) error {

	var err error                                      // for error handling
	var resp arangodb.CollectionDocumentCreateResponse // data about the document
	var ctx = context.Background()                     // use default database context
	compver := model.NewComponentVersionDetails()      // define a compver to be returned

	if err = c.BodyParser(compver); err != nil { // parse the JSON into the compver object
		return c.Status(503).Send([]byte(err.Error()))
	}

	// Initialize Resty client
	client := resty.New()

	// get the OSSF Scorecard
	var scorecard = model.NewScorecard()

	url := ""
	if compver.Attrs.GitURL != "" {
		if compver.Attrs.GitCommit != "" {
			url = "http://localhost:8083/msapi/scorecard/" + convertGitURL(compver.Attrs.GitURL) + "?commit=" + compver.Attrs.GitCommit
		} else {
			url = "http://localhost:8083/msapi/scorecard/" + convertGitURL(compver.Attrs.GitURL)
		}
	}

	if url != "" {
		if _, err = client.R().
			SetResult(scorecard).
			Get(url); err != nil {
			logger.Sugar().Infof("Scorecard Error=%v\n", err)
		}
	}
	compver.Scorecard = scorecard

	cid, dbStr := database.MakeNFT(compver) // normalize the object into NFTs and JSON string for db persistence

	logger.Sugar().Infof("%s=%s\n", cid, dbStr) // log the new nft

	// add the compver to the database.  Ignore if it already exists since it will be identical
	if resp, err = dbconn.Collections["components"].CreateDocument(ctx, compver); err != nil && !shared.IsConflict(err) {
		logger.Sugar().Errorf("Failed to create document: %v", err)
	}

	meta := resp.DocumentMeta
	logger.Sugar().Infof("Created document in collection '%s' in db '%s' key='%s'\n", dbconn.Collections["components"].Name(), dbconn.Database.Name(), meta.Key)

	return c.JSON(compver) // return the compver object in JSON format.  This includes the new _key
}

// HealthCheck for kubernetes to determine if it is in a good state
func HealthCheck(c *fiber.Ctx) error {
	return c.SendString("OK")
}

// setupRoutes defines maps the routes to the functions
func setupRoutes(app *fiber.App) {

	app.Get("/swagger/*", swagger.HandlerDefault)              // handle displaying the swagger
	app.Get("/msapi/compver", GetComponentVersions)            // list of compvers
	app.Get("/msapi/compver/:key", GetComponentVersionDetails) // single compver based on name or key
	app.Post("/msapi/compver", NewComponentVersionDetails)     // save a single compver
	app.Get("/health", HealthCheck)                            // Health check endpoint
}

// @title Ortelius v11 ComponentVersion Microservice
// @version 11.0.0
// @description RestAPI for the ComponentVersion Object
// @description ![Release](https://img.shields.io/github/v/release/ortelius/scec-compver?sort=semver)
// @description ![license](https://img.shields.io/github/license/ortelius/.github)
// @description
// @description ![Build](https://img.shields.io/github/actions/workflow/status/ortelius/scec-compver/build-push-chart.yml)
// @description [![MegaLinter](https://github.com/ortelius/scec-compver/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/scec-compver/actions?query=workflow%3AMegaLinter+branch%3Amain)
// @description ![CodeQL](https://github.com/ortelius/scec-compver/workflows/CodeQL/badge.svg)
// @description [![OpenSSF-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/scec-compver/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/scec-compver)
// @description
// @description ![Discord](https://img.shields.io/discord/722468819091849316)

// @termsOfService http://swagger.io/terms/
// @contact.name Ortelius Google Group
// @contact.email ortelius-dev@googlegroups.com
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:3000
// @BasePath /msapi/compver
func main() {
	port := ":" + database.GetEnvDefault("MS_PORT", "8080") // database port
	app := fiber.New()                                      // create a new fiber application
	app.Use(cors.New(cors.Config{
		AllowHeaders: "Origin, Content-Type, Accept",
		AllowOrigins: "*",
	}))

	setupRoutes(app) // define the routes for this microservice

	if err := app.Listen(port); err != nil { // start listening for incoming connections
		logger.Sugar().Fatalf("Failed get the microservice running: %v", err)
	}
}
