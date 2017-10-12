// THIS IS A ROUGH SKETCH
// This is the beginning work of adding an Idler CRD, replacing the dependence on 
// annotations.
// controller code needs to be edited to reflect the change to CRD
// This is not ready for any kind of review yet.. this code does not work yet
// file pkg/idling/apis/types.go
package blah

import (
	autoscaling "k8s.io/kubernetes/pkg/apis/autoscaling/v1"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
)

var idlerDefinition = apiextv1beta1.CustomResourceDefinition{
	ObjectMeta: metav1.ObjectMeta{
		Name: "idlers.idling.openshift.io"
	},
	Spec: apiextv1beta1.CustomResourceDefinitionSpec{
		Group:   "idling.openshift.io",
		Version: "v1alpha1",
		Scope:   apiextv1beta1.NamespaceScoped,
		Names:   apiextv1beta1.CustomResourceDefinitionNames{
			Plural: "idlers",
			ShortNames: []string{"idl"},
			Kind:   "Idler",
		},
	},
}

type IdleState string
const (
	Idled IdleState = "idled"
	Unidled IdleState = "unidled"
)

type Idler struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec               IdlerSpec   `json:"spec"`
	Status             IdlerStatus `json:"status,omitempty"`
}

type IdlerSpec struct {
	Scalables ScaleInfo `json:"scalables"`
	Services []string   `json:"services"`
	State IdleState
}

type ScaleInfo struct {
	Target autoscaling.CrossVersionObjectReference
	Replicas int32
}

type IdlerStatus struct {
	CurrentState       IdleState      `json:"currentState,omitempty"`   // "idled"/"unidled"
	ObservedGeneration metav1.Time    `json:"lastTransition,omitempty"` // ResourceVersion
}

type IdlerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items            []Idler `json:"items"`
}

// Create a  Rest client with the new CRD Schema
var SchemeGroupVersion = schema.GroupVersion{Group: "idling.openshift.io", Version: "v1alpha1"}

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&Idler{},
		&IdlerList{},
	)
	meta_v1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// Create the CRD Idler resource, ignore error if it already exists
func RegisterDefinition(clientset apiextcs.Interface) error {
	_, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Create(idlerDefinition)
	if err != nil && apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// below in another file pkg/idling/client/client.go
// Look at existing apis, model file structure after them

var scheme = runtime.NewScheme()
func init() {
	addKnownTypes(scheme)
}


func NewClient(cfg *rest.Config) (*rest.RESTClient, *runtime.Scheme, error) {
	config := *cfg
	config.GroupVersion = &SchemeGroupVersion
	config.APIPath = "/apis"
	config.ContentType = runtime.ContentTypeJSON
	config.NegotiatedSerializer = serializer.DirectCodecFactory{
		CodecFactory: serializer.NewCodecFactory(scheme)
	}

	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, nil, err
	}
	return client, scheme, nil
}
