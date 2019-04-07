package release

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/golang/glog"
	digest "github.com/opencontainers/go-digest"
	"github.com/spf13/cobra"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	kcmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
	"k8s.io/kubernetes/pkg/kubectl/util/templates"

	configv1client "github.com/openshift/client-go/config/clientset/versioned"
	"github.com/openshift/origin/pkg/image/apis/image/docker10"
	imagereference "github.com/openshift/origin/pkg/image/apis/image/reference"
	"github.com/openshift/origin/pkg/oc/cli/image/extract"
)

func NewExtractOptions(streams genericclioptions.IOStreams) *ExtractOptions {
	return &ExtractOptions{
		IOStreams: streams,
		Directory: ".",
	}
}

func NewExtract(f kcmdutil.Factory, parentName string, streams genericclioptions.IOStreams) *cobra.Command {
	o := NewExtractOptions(streams)
	cmd := &cobra.Command{
		Use:   "extract",
		Short: "Extract the contents of an update payload to disk",
		Long: templates.LongDesc(`
			Extract the contents of a release image to disk

			Extracts the contents of an OpenShift release image to disk for inspection or
			debugging. Update images contain manifests and metadata about the operators that
			must be installed on the cluster for a given version.

			The --tools and --command flags allow you to extract the appropriate client binaries
			for	your operating system to disk. --tools will create archive files containing the
			current OS tools (or, if --command-os is set to '*', all OS versions). Specifying
			--command for either 'oc' or 'openshift-install' will extract the binaries directly.

			Instead of extracting the manifests, you can specify --git=DIR to perform a Git
			checkout of the source code that comprises the release. A warning will be printed
			if the component is not associated with source code. The command will not perform
			any destructive actions on your behalf except for executing a 'git checkout' which
			may change the current branch. Requires 'git' to be on your path.
		`),
		Run: func(cmd *cobra.Command, args []string) {
			kcmdutil.CheckErr(o.Complete(f, cmd, args))
			kcmdutil.CheckErr(o.Run())
		},
	}
	flags := cmd.Flags()
	flags.StringVarP(&o.RegistryConfig, "registry-config", "a", o.RegistryConfig, "Path to your registry credentials (defaults to ~/.docker/config.json)")

	flags.StringVar(&o.From, "from", o.From, "Image containing the release payload.")
	flags.StringVar(&o.File, "file", o.File, "Extract a single file from the payload to standard output.")
	flags.StringVar(&o.Directory, "to", o.Directory, "Directory to write release contents to, defaults to the current directory.")

	flags.StringVar(&o.GitExtractDir, "git", o.GitExtractDir, "Check out the sources that created this release into the provided dir. Repos will be created at <dir>/<host>/<path>. Requires 'git' on your path.")
	flags.BoolVar(&o.Tools, "tools", o.Tools, "Extract the tools archives from the release image. Implies --command=*")

	flags.StringVar(&o.Command, "command", o.Command, "Specify 'oc' or 'openshift-install' to extract the client for your operating system.")
	flags.StringVar(&o.CommandOperatingSystem, "command-os", o.CommandOperatingSystem, "Override which operating system command is extracted (mac, windows, linux). You map specify '*' to extract all tool archives.")
	return cmd
}

type ExtractOptions struct {
	genericclioptions.IOStreams

	From string

	Tools                  bool
	Command                string
	CommandOperatingSystem string

	// GitExtractDir is the path of a root directory to extract the source of a release to.
	GitExtractDir string

	Directory string
	File      string

	RegistryConfig string

	ImageMetadataCallback func(m *extract.Mapping, dgst digest.Digest, config *docker10.DockerImageConfig)
}

func (o *ExtractOptions) Complete(f kcmdutil.Factory, cmd *cobra.Command, args []string) error {
	switch {
	case len(args) == 0 && len(o.From) == 0:
		cfg, err := f.ToRESTConfig()
		if err != nil {
			return fmt.Errorf("info expects one argument, or a connection to an OpenShift 4.x server: %v", err)
		}
		client, err := configv1client.NewForConfig(cfg)
		if err != nil {
			return fmt.Errorf("info expects one argument, or a connection to an OpenShift 4.x server: %v", err)
		}
		cv, err := client.ConfigV1().ClusterVersions().Get("version", metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Errorf("you must be connected to an OpenShift 4.x server to fetch the current version")
			}
			return fmt.Errorf("info expects one argument, or a connection to an OpenShift 4.x server: %v", err)
		}
		image := cv.Status.Desired.Image
		if len(image) == 0 && cv.Spec.DesiredUpdate != nil {
			image = cv.Spec.DesiredUpdate.Image
		}
		if len(image) == 0 {
			return fmt.Errorf("the server is not reporting a release image at this time, please specify an image to extract")
		}
		o.From = image

	case len(args) == 1 && len(o.From) > 0, len(args) > 1:
		return fmt.Errorf("you may only specify a single image via --from or argument")

	case len(args) == 1:
		o.From = args[0]
	}
	return nil
}

func (o *ExtractOptions) Run() error {
	sources := 0
	if o.Tools {
		sources++
	}
	if len(o.File) > 0 {
		sources++
	}
	if len(o.Command) > 0 {
		sources++
	}
	if len(o.GitExtractDir) > 0 {
		sources++
	}

	switch {
	case sources > 1:
		return fmt.Errorf("only one of --tools, --command, --file, or --git may be specified")
	case len(o.From) == 0:
		return fmt.Errorf("must specify an image containing a release payload with --from")
	case o.Directory != "." && len(o.File) > 0:
		return fmt.Errorf("only one of --to and --file may be set")

	case len(o.GitExtractDir) > 0:
		return o.extractGit(o.GitExtractDir)
	case o.Tools:
		return o.extractTools()
	case len(o.Command) > 0:
		return o.extractCommand(o.Command)
	}

	dir := o.Directory
	if err := os.MkdirAll(dir, 0777); err != nil {
		return err
	}

	src := o.From
	ref, err := imagereference.Parse(src)
	if err != nil {
		return err
	}
	opts := extract.NewOptions(genericclioptions.IOStreams{Out: o.Out, ErrOut: o.ErrOut})
	opts.RegistryConfig = o.RegistryConfig

	switch {
	case len(o.File) > 0:
		if o.ImageMetadataCallback != nil {
			opts.ImageMetadataCallback = o.ImageMetadataCallback
		}
		opts.OnlyFiles = true
		opts.Mappings = []extract.Mapping{
			{
				ImageRef: ref,

				From: "release-manifests/",
				To:   dir,
			},
		}
		found := false
		opts.TarEntryCallback = func(hdr *tar.Header, _ extract.LayerInfo, r io.Reader) (bool, error) {
			if hdr.Name != o.File {
				return true, nil
			}
			if _, err := io.Copy(o.Out, r); err != nil {
				return false, err
			}
			found = true
			return false, nil
		}
		if err := opts.Run(); err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("image did not contain %s", o.File)
		}
		return nil

	default:
		opts.OnlyFiles = true
		opts.Mappings = []extract.Mapping{
			{
				ImageRef: ref,

				From: "release-manifests/",
				To:   dir,
			},
		}
		opts.ImageMetadataCallback = func(m *extract.Mapping, dgst digest.Digest, config *docker10.DockerImageConfig) {
			if o.ImageMetadataCallback != nil {
				o.ImageMetadataCallback(m, dgst, config)
			}
			if len(ref.ID) > 0 {
				fmt.Fprintf(o.Out, "Extracted release payload created at %s\n", config.Created.Format(time.RFC3339))
			} else {
				fmt.Fprintf(o.Out, "Extracted release payload from digest %s created at %s\n", dgst, config.Created.Format(time.RFC3339))
			}
		}
		return opts.Run()
	}
}

func (o *ExtractOptions) extractGit(dir string) error {
	if err := os.MkdirAll(dir, 0777); err != nil {
		return err
	}

	release, err := NewInfoOptions(o.IOStreams).LoadReleaseInfo(o.From, false)
	if err != nil {
		return err
	}

	hadErrors := false
	alreadyExtracted := make(map[string]string)
	for _, ref := range release.References.Spec.Tags {
		repo := ref.Annotations[annotationBuildSourceLocation]
		commit := ref.Annotations[annotationBuildSourceCommit]
		if len(repo) == 0 || len(commit) == 0 {
			if glog.V(2) {
				glog.Infof("Tag %s has no source info", ref.Name)
			} else {
				fmt.Fprintf(o.ErrOut, "warning: Tag %s has no source info\n", ref.Name)
			}
			continue
		}
		if oldCommit, ok := alreadyExtracted[repo]; ok {
			if oldCommit != commit {
				fmt.Fprintf(o.ErrOut, "warning: Repo %s referenced more than once with different commits, only checking out the first reference\n", repo)
			}
			continue
		}
		alreadyExtracted[repo] = commit

		extractedRepo, err := ensureCloneForRepo(dir, repo, nil, o.Out, o.ErrOut)
		if err != nil {
			hadErrors = true
			fmt.Fprintf(o.ErrOut, "error: cloning %s: %v\n", repo, err)
			continue
		}

		glog.V(2).Infof("Checkout %s from %s ...", commit, repo)
		if err := extractedRepo.CheckoutCommit(repo, commit); err != nil {
			hadErrors = true
			fmt.Fprintf(o.ErrOut, "error: checking out commit for %s: %v\n", repo, err)
			continue
		}
	}
	if hadErrors {
		return kcmdutil.ErrExit
	}
	return nil
}
