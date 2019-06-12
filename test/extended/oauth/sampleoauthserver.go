package oauth

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"

	g "github.com/onsi/ginkgo"
	o "github.com/onsi/gomega"

	e2e "k8s.io/kubernetes/test/e2e/framework"

	osinv1 "github.com/openshift/api/osin/v1"
	exutil "github.com/openshift/origin/test/extended/util"
)

var _ = g.Describe("[Suite:openshift/oauth/run-oauth-server] Run the integrated OAuth server", func() {
	defer g.GinkgoRecover()
	var (
		oc = exutil.NewCLI("oauth-server-configure", exutil.KubeConfigPath())
	)

	g.It("should successfully be configured and be responsive", func() {
		serverAddress, cleanup, err := exutil.DeployOAuthServer(oc, []osinv1.IdentityProvider{})
		defer cleanup()
		o.Expect(err).ToNot(o.HaveOccurred())
		e2e.Logf("got the OAuth server address: %s", serverAddress)

		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // FIXME: VERY VERY UGLY, don't do this at home
		resp, err := http.Get(serverAddress)
		o.Expect(err).ToNot(o.HaveOccurred())
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		e2e.Logf("The body received: %s", string(body))
		o.Expect(err).ToNot(o.HaveOccurred())
	})
})
