package oauth

import (
	"io/ioutil"
	"net/http"

	g "github.com/onsi/ginkgo"
	o "github.com/onsi/gomega"

	"k8s.io/client-go/rest"
	e2e "k8s.io/kubernetes/test/e2e/framework"

	osinv1 "github.com/openshift/api/osin/v1"
	exutil "github.com/openshift/origin/test/extended/util"
)

// TODO: No Serial, currently failing w/ parallel
var _ = g.Describe("[Serial][Suite:openshift/oauth/run-oauth-server] Run the integrated OAuth server", func() {
	defer g.GinkgoRecover()
	var (
		oc = exutil.NewCLI("test-oauth", exutil.KubeConfigPath())
	)

	g.It("should successfully be configured and be responsive", func() {
		serverAddress, cleanup, err := exutil.DeployOAuthServer(oc, []osinv1.IdentityProvider{})
		defer cleanup()
		o.Expect(err).ToNot(o.HaveOccurred())
		e2e.Logf("got the OAuth server address: %s", serverAddress)

		tlsClientConfig, err := rest.TLSConfigFor(oc.AdminConfig())
		o.Expect(err).NotTo(o.HaveOccurred())
		http.DefaultTransport.(*http.Transport).TLSClientConfig = tlsClientConfig
		resp, err := http.Get(serverAddress)
		o.Expect(err).ToNot(o.HaveOccurred())
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		e2e.Logf("The body received: %s", string(body))
		o.Expect(err).ToNot(o.HaveOccurred())
	})
	//TODO:  haven't gotten to adding a different check here
	// This is failing atm, problem w/ htpasswd file/secret
	g.It("should successfully configure htpasswd", func() {
		serverAddress, cleanup, err := exutil.DeployOAuthServer(oc, exutil.Htpasswd())
		defer cleanup()
		o.Expect(err).ToNot(o.HaveOccurred())
		e2e.Logf("got the OAuth server address: %s", serverAddress)

		tlsClientConfig, err := rest.TLSConfigFor(oc.AdminConfig())
		o.Expect(err).NotTo(o.HaveOccurred())
		http.DefaultTransport.(*http.Transport).TLSClientConfig = tlsClientConfig
		resp, err := http.Get(serverAddress)
		o.Expect(err).ToNot(o.HaveOccurred())
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		e2e.Logf("The body received: %s", string(body))
		o.Expect(err).ToNot(o.HaveOccurred())
	})
})
