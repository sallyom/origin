package util

import (
	"fmt"
	"path"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"

	configv1 "github.com/openshift/api/config/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	"github.com/openshift/library-go/pkg/crypto"
)

const (
	serviceURLFmt = "https://test-oauth-svc.%s.svc" // fill in the namespace

	servingCertPathCert = "/var/config/system/secrets/serving-cert/tls.crt"
	servingCertPathKey  = "/var/config/system/secrets/serving-cert/tls.key"
	sessionSecretPath   = "/var/config/system/secrets/session/session"

	RouteName = "test-oauth-route"
	SAName    = "e2e-oauth"
)

var (
	serviceCAPath = "/var/config/system/configmaps/service-ca/service-ca.crt" // has to be var so that we can use its address

	osinScheme = runtime.NewScheme()
	codecs     = serializer.NewCodecFactory(osinScheme)
	encoder    = codecs.LegacyCodec(osinv1.GroupVersion)
)

func init() {
	utilruntime.Must(osinv1.Install(osinScheme))
}

// DeployOAuthServer - deployes an instance of an OpenShift OAuth server
// very simplified for now
// returns OAuth server url, cleanup function, error
func DeployOAuthServer(oc *CLI, idps []osinv1.IdentityProvider) (string, func(), error) {
	oauthServerDataDir := FixturePath("testdata", "oauthserver")
	cleanups := func() {
		oc.AsAdmin().Run("delete").Args("clusterrolebinding", SAName).Execute()
	}

	if err := oc.AsAdmin().Run("create").Args("-f", path.Join(oauthServerDataDir, "oauth-sa.yaml")).Execute(); err != nil {
		return "", cleanups, err
	}

	// the oauth server needs access to kube-system configmaps/extension-apiserver-authentication
	oauthSARolebinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: SAName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "cluster-admin", // FIXME: Nope!
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      SAName,
				Namespace: oc.Namespace(),
			},
		},
	}
	if _, err := oc.AdminKubeClient().RbacV1().ClusterRoleBindings().Create(oauthSARolebinding); err != nil {
		return "", cleanups, err
	}

	// FIXME: autogenerate the session secret
	for _, res := range []string{"session-secret.yaml", "cabundle-cm.yaml", "oauth-server.yaml"} {
		if err := oc.AsAdmin().Run("create").Args("-f", path.Join(oauthServerDataDir, res)).Execute(); err != nil {
			return "", cleanups, err
		}
	}

	route, err := oc.AdminRouteClient().Route().Routes(oc.Namespace()).Get(RouteName, metav1.GetOptions{})
	if err != nil {
		return "", cleanups, err
	}
	routeURL := fmt.Sprintf("https://%s", route.Spec.Host)

	// prepare the configX
	config, err := oauthServerConfig(oc, routeURL, idps) // TODO: add IdPs here
	if err != nil {
		return "", cleanups, err
	}

	configBytes := encode(config)
	if configBytes == nil {
		return "", cleanups, fmt.Errorf("error encoding the OSIN config")
	}

	if err = oc.AsAdmin().Run("create").Args("configmap", "oauth-config", "--from-literal", fmt.Sprintf("oauth.conf=%s", string(configBytes))).Execute(); err != nil {
		return "", cleanups, err
	}

	err = wait.PollImmediate(1*time.Second, 45*time.Second, func() (bool, error) {
		pod, err := oc.AdminKubeClient().CoreV1().Pods(oc.Namespace()).Get("test-oauth-server", metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return CheckPodIsReady(*pod), nil
	})
	if err != nil {
		return "", cleanups, err
	}

	return routeURL, cleanups, nil
}

// TODO:consider: we could just as well grab whatever config there is in openshift-authentication
// namespace and interpolate it with our values
// TODO: add []osinv1.IdentityProvider as input?
func oauthServerConfig(oc *CLI, routeURL string, idps []osinv1.IdentityProvider) (*osinv1.OsinServerConfig, error) {
	adminConfigClient := configclient.NewForConfigOrDie(oc.AdminConfig()).ConfigV1()

	infrastructure, err := adminConfigClient.Infrastructures().Get("cluster", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	console, err := adminConfigClient.Consoles().Get("cluster", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return &osinv1.OsinServerConfig{
		GenericAPIServerConfig: configv1.GenericAPIServerConfig{
			ServingInfo: configv1.HTTPServingInfo{
				ServingInfo: configv1.ServingInfo{
					BindAddress: "0.0.0.0:6443",
					BindNetwork: "tcp4",
					// we have valid serving certs provided by service-ca
					// this is our main server cert which is used if SNI does not match
					CertInfo: configv1.CertInfo{
						CertFile: servingCertPathCert,
						KeyFile:  servingCertPathKey,
					},
					ClientCA: "", // I think this can be left unset
					// NamedCertificates: routerSecretToSNI(routerSecret), <--- might be necessary for request headers IdP
					MinTLSVersion: crypto.TLSVersionToNameOrDie(crypto.DefaultTLSVersion()),
					CipherSuites:  crypto.CipherSuitesToNamesOrDie(crypto.DefaultCiphers()),
				},
				MaxRequestsInFlight:   1000,   // TODO this is a made up number
				RequestTimeoutSeconds: 5 * 60, // 5 minutes
			},
			// TODO: see if we need CORS set
			// CORSAllowedOrigins: corsAllowedOrigins,     // set console route as valid CORS (so JS can logout)
			AuditConfig: configv1.AuditConfig{}, // TODO probably need this
			KubeClientConfig: configv1.KubeClientConfig{
				KubeConfig: "", // this should use in cluster config
				ConnectionOverrides: configv1.ClientConnectionOverrides{
					QPS:   400, // TODO figure out values
					Burst: 400,
				},
			},
		},
		OAuthConfig: osinv1.OAuthConfig{
			MasterCA:                    &serviceCAPath, // we have valid serving certs provided by service-ca so we can use the service for loopback
			MasterURL:                   fmt.Sprintf(serviceURLFmt, oc.Namespace()),
			MasterPublicURL:             routeURL,
			LoginURL:                    infrastructure.Status.APIServerURL,
			AssetPublicURL:              console.Status.ConsoleURL, // set console route as valid 302 redirect for logout
			AlwaysShowProviderSelection: false,
			IdentityProviders:           idps,
			GrantConfig: osinv1.GrantConfig{
				Method:               osinv1.GrantHandlerDeny, // force denial as this field must be set per OAuth client
				ServiceAccountMethod: osinv1.GrantHandlerPrompt,
			},
			SessionConfig: &osinv1.SessionConfig{
				SessionSecretsFile:   sessionSecretPath,
				SessionMaxAgeSeconds: 5 * 60, // 5 minutes
				SessionName:          "ssn",
			},
			TokenConfig: osinv1.TokenConfig{
				AuthorizeTokenMaxAgeSeconds: 5 * 60,       // 5 minutes
				AccessTokenMaxAgeSeconds:    24 * 60 * 60, // 1 day
				// AccessTokenInactivityTimeoutSeconds: xxx, TODO: see whether we need this
			},
			//  Templates: templates, TODO: we might eventually want this
		},
	}, nil
}

func encode(obj runtime.Object) []byte {
	bytes, err := runtime.Encode(encoder, obj)
	if err != nil {
		return nil
	}
	return bytes
}
