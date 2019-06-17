package util

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"path"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	//apierrs "k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"

	configv1 "github.com/openshift/api/config/v1"
	legacyconfigv1 "github.com/openshift/api/legacyconfig/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	"github.com/openshift/library-go/pkg/crypto"
)

const (
	htpasswdFile  = "/var/config/system/secrets/htpasswd"
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
	ns := oc.Namespace()
	clusterRoleBindingName := fmt.Sprintf(SAName + ns[21:23])
	cleanups := func() {
		oc.AsAdmin().Run("delete").Args("clusterrolebinding", clusterRoleBindingName).Execute()
	}

	if err := oc.AsAdmin().Run("create").Args("-f", path.Join(oauthServerDataDir, "oauth-sa.yaml")).Execute(); err != nil {
		return "", cleanups, err
	}

	// the oauth server needs access to kube-system configmaps/extension-apiserver-authentication
	oauthSARolebinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterRoleBindingName,
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
				Namespace: ns,
			},
		},
	}
	if _, err := oc.AdminKubeClient().RbacV1().ClusterRoleBindings().Create(oauthSARolebinding); err != nil {
		return "", cleanups, err
	}

	sessionSecret, err := randomSessionSecret(ns)
	if err != nil {
		return "", cleanups, err
	}
	if _, err := oc.AdminKubeClient().CoreV1().Secrets(ns).Create(sessionSecret); err != nil {
		return "", cleanups, err
	}

	for _, res := range []string{"cabundle-cm.yaml", "oauth-server.yaml"} {
		if err := oc.AsAdmin().Run("create").Args("-f", path.Join(oauthServerDataDir, res)).Execute(); err != nil {
			return "", cleanups, err
		}
	}

	// there's probably a better way to do this, have to think about it...
	if len(idps) == 0 {
		if err := oc.AsAdmin().Run("create").Args("-f", path.Join(oauthServerDataDir, "pod-oauth-noidp.yaml")).Execute(); err != nil {
			return "", cleanups, err
		}
	} else {
		switch idps[0].Name {
		// we'll have other idps
		case "htpasswd":
			for _, res := range []string{"htpasswd-data.yaml", "pod-oauth-htpasswd.yaml"} {
				if err := oc.AsAdmin().Run("create").Args("-f", path.Join(oauthServerDataDir, res)).Execute(); err != nil {
					return "", cleanups, err
				}
			}
		}
	}

	route, err := oc.AdminRouteClient().RouteV1().Routes(ns).Get(RouteName, metav1.GetOptions{})
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
		pod, err := oc.AdminKubeClient().CoreV1().Pods(ns).Get("test-oauth-server", metav1.GetOptions{})
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

func Htpasswd() []osinv1.IdentityProvider {
	idp := osinv1.IdentityProvider{
		Name:            "htpasswd",
		UseAsChallenger: true,
		UseAsLogin:      true,
		MappingMethod:   "claim",
		Provider:        runtime.RawExtension{Object: &osinv1.HTPasswdPasswordIdentityProvider{File: htpasswdFile}},
	}
	return []osinv1.IdentityProvider{idp}
}

func encode(obj runtime.Object) []byte {
	bytes, err := runtime.Encode(encoder, obj)
	if err != nil {
		return nil
	}
	return bytes
}

func randomSessionSecret(ns string) (*corev1.Secret, error) {
	skey, err := newSessionSecretsJSON()
	if err != nil {
		return nil, err
	}
	meta := metav1.ObjectMeta{
		Name:      "session",
		Namespace: ns,
		Labels: map[string]string{
			"app": "test-oauth-server",
		},
		Annotations:     map[string]string{},
		OwnerReferences: nil,
	}
	return &corev1.Secret{
		ObjectMeta: meta,
		Data: map[string][]byte{
			"session": skey,
		},
	}, nil
}

// this is less random than the actual secret generated in cluster-authentication-operator
func newSessionSecretsJSON() ([]byte, error) {
	const (
		sha256KeyLenBytes = sha256.BlockSize // max key size with HMAC SHA256
		aes256KeyLenBytes = 32               // max key size with AES (AES-256)
	)

	secrets := &legacyconfigv1.SessionSecrets{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SessionSecrets",
			APIVersion: "v1",
		},
		Secrets: []legacyconfigv1.SessionSecret{
			{
				Authentication: randomString(sha256KeyLenBytes), // 64 chars
				Encryption:     randomString(aes256KeyLenBytes), // 32 chars
			},
		},
	}
	secretsBytes, err := json.Marshal(secrets)
	if err != nil {
		return nil, fmt.Errorf("error marshalling the session secret: %v", err) // should never happen
	}

	return secretsBytes, nil
}

//randomString - random string of A-Z chars with len size
func randomString(size int) string {
	bytes := make([]byte, size)
	for i := 0; i < size; i++ {
		bytes[i] = byte(65 + rand.Intn(25))
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}
