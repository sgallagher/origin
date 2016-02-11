// +build integration

package integration

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	knet "k8s.io/kubernetes/pkg/util/net"

	configapi "github.com/openshift/origin/pkg/cmd/server/api"
	testutil "github.com/openshift/origin/test/util"
	testserver "github.com/openshift/origin/test/util/server"
)

func templateEscape(s string) (string, error) {
	temp := new(bytes.Buffer)

	t, err := template.New("foo").Parse(`{{define "T"}}{{.}}{{end}}`)
	if err != nil {
		return "", err
	}
	err = t.ExecuteTemplate(temp, "T", s)
	if err != nil {
		return "", err
	}

	return temp.String(), nil
}

func tryAccessURL(t *testing.T, url string, expectedStatus int, expectedRedirectLocation string, expectedLinks []string) *http.Response {
	transport := knet.SetTransportDefaults(&http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	})

	req, err := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "text/html")
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Errorf("Unexpected error while accessing %q: %v", url, err)
		return nil
	}
	if resp.StatusCode != expectedStatus {
		t.Errorf("Expected status %d for %q, got %d", expectedStatus, url, resp.StatusCode)
	}
	// ignore query parameters
	location := resp.Header.Get("Location")
	location = strings.SplitN(location, "?", 2)[0]
	if location != expectedRedirectLocation {
		t.Errorf("Expected redirection to %q for %q, got %q instead", expectedRedirectLocation, url, location)
	}

	if expectedLinks != nil {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("failed to read reposponse's body: %v", err)
		} else {
			for _, linkRegexp := range expectedLinks {
				matched, err := regexp.Match(linkRegexp, body)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else if !matched {
					t.Errorf("Expected a link matching %q in response body.", linkRegexp)
				}
			}
		}
	}

	return resp
}

func TestAccessOriginWebConsole(t *testing.T) {
	testutil.RequireEtcd(t)
	masterOptions, err := testserver.DefaultMasterOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err = testserver.StartConfiguredMaster(masterOptions); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for endpoint, exp := range map[string]struct {
		statusCode int
		location   string
	}{
		"":                    {http.StatusFound, masterOptions.AssetConfig.PublicURL},
		"healthz":             {http.StatusOK, ""},
		"login":               {http.StatusOK, ""},
		"oauth/token/request": {http.StatusFound, masterOptions.AssetConfig.MasterPublicURL + "/oauth/authorize"},
		"console":             {http.StatusMovedPermanently, "/console/"},
		"console/":            {http.StatusOK, ""},
		"console/java":        {http.StatusOK, ""},
	} {
		url := masterOptions.AssetConfig.MasterPublicURL + "/" + endpoint
		tryAccessURL(t, url, exp.statusCode, exp.location, nil)
	}
}

func TestAccessDisabledWebConsole(t *testing.T) {
	testutil.RequireEtcd(t)
	masterOptions, err := testserver.DefaultMasterOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	masterOptions.DisabledFeatures.Add(configapi.FeatureWebConsole)
	if _, err := testserver.StartConfiguredMaster(masterOptions); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp := tryAccessURL(t, masterOptions.AssetConfig.MasterPublicURL+"/", http.StatusOK, "", nil)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("failed to read reposponse's body: %v", err)
	} else {
		var value interface{}
		if err = json.Unmarshal(body, &value); err != nil {
			t.Errorf("expected json body which couldn't be parsed: %v, got: %s", err, body)
		}
	}

	for endpoint, exp := range map[string]struct {
		statusCode int
		location   string
	}{
		"healthz":             {http.StatusOK, ""},
		"login":               {http.StatusOK, ""},
		"oauth/token/request": {http.StatusFound, masterOptions.AssetConfig.MasterPublicURL + "/oauth/authorize"},
		"console":             {http.StatusForbidden, ""},
		"console/":            {http.StatusForbidden, ""},
		"console/java":        {http.StatusForbidden, ""},
	} {
		url := masterOptions.AssetConfig.MasterPublicURL + "/" + endpoint
		tryAccessURL(t, url, exp.statusCode, exp.location, nil)
	}
}

func TestAccessOriginWebConsoleMultipleIdentityProviders(t *testing.T) {
	testutil.RequireEtcd(t)
	masterOptions, err := testserver.DefaultMasterOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Replace the default IdentityProvider with an AllowAll provider
	masterOptions.OAuthConfig.IdentityProviders[0] = configapi.IdentityProvider{
		Name:            "foo",
		UseAsChallenger: true,
		UseAsLogin:      true,
		MappingMethod:   "claim",
		Provider:        &configapi.AllowAllPasswordIdentityProvider{},
	}

	// Set up a second AllowAll provider
	masterOptions.OAuthConfig.IdentityProviders = append(masterOptions.OAuthConfig.IdentityProviders, configapi.IdentityProvider{
		Name:            "bar",
		UseAsChallenger: true,
		UseAsLogin:      true,
		MappingMethod:   "claim",
		Provider:        &configapi.AllowAllPasswordIdentityProvider{},
	})

	// Set up a third AllowAll provider with a space in the name and some
	// unicode characters
	masterOptions.OAuthConfig.IdentityProviders = append(masterOptions.OAuthConfig.IdentityProviders, configapi.IdentityProvider{
		Name:            "baz qux #2",
		UseAsChallenger: true,
		UseAsLogin:      true,
		MappingMethod:   "claim",
		Provider:        &configapi.AllowAllPasswordIdentityProvider{},
	})

	// Launch the configured server
	if _, err = testserver.StartConfiguredMaster(masterOptions); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Create a map of URLs to test
	type urlResults struct {
		statusCode int
		location   string
	}

	urlMap := make(map[string]urlResults)
	linkRegexps := make([]string, 0)

	// Verify that the plain /login URI is unavailable when multiple IDPs
	// are in use.
	urlMap["/login"] = urlResults{http.StatusForbidden, ""}

	// Create the common base URLs
	escapedPublicURL := url.QueryEscape(masterOptions.OAuthConfig.AssetPublicURL)
	loginSelectorBase := "/oauth/authorize?client_id=openshift-web-console&response_type=token&state=%2F&redirect_uri=" + escapedPublicURL

	// Iterate through each of the providers and verify that they redirect to
	// the appropriate login page and that the login page exists.
	// This is done in a loop so that we can add an arbitrary additional set
	// of providers to test.
	for _, value := range masterOptions.OAuthConfig.IdentityProviders {
		templateEscapedName, err := templateEscape(value.Name)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		queryEscapedName := template.URLQueryEscaper(templateEscapedName)

		// Path to the login URI is template-escaped, then query-escaped, then has the + substituted with %20
		loginPathName := strings.Replace(queryEscapedName, "+", "%20", -1)

		urlMap[loginSelectorBase+"&idp="+queryEscapedName] = urlResults{http.StatusFound, "/login/" + loginPathName}
		urlMap["/login/"+loginPathName] = urlResults{http.StatusOK, ""}

		// The name in the regular expression needs to be template-escaped again
		regexpName, err := templateEscape(queryEscapedName)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		linkRegexps = append(linkRegexps, fmt.Sprintf("/oauth/authorize\\?(.*)(&amp;)?idp=%s(&amp;|$)", regexp.QuoteMeta(regexpName)))
	}

	// Test the loginSelectorBase for links to all of the IDPs
	url := masterOptions.AssetConfig.MasterPublicURL + loginSelectorBase
	tryAccessURL(t, url, http.StatusOK, "", linkRegexps)

	// Test all of these URLs
	for endpoint, exp := range urlMap {
		url := masterOptions.AssetConfig.MasterPublicURL + endpoint
		tryAccessURL(t, url, exp.statusCode, exp.location, nil)
	}
}
