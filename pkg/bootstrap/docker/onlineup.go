package docker

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"

	"github.com/blang/semver"
	dockerclient "github.com/docker/engine-api/client"
	docker "github.com/fsouza/go-dockerclient"
	"github.com/golang/glog"
	"github.com/spf13/cobra"

	kclient "k8s.io/kubernetes/pkg/client/unversioned"
	kclientcmd "k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	kcmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"

	"github.com/openshift/origin/pkg/bootstrap/docker/dockerhelper"
	"github.com/openshift/origin/pkg/bootstrap/docker/dockermachine"
	"github.com/openshift/origin/pkg/bootstrap/docker/errors"
	"github.com/openshift/origin/pkg/bootstrap/docker/host"
	"github.com/openshift/origin/pkg/bootstrap/docker/openshift"
	"github.com/openshift/origin/pkg/client"
	"github.com/openshift/origin/pkg/cmd/util/clientcmd"
	osclientcmd "github.com/openshift/origin/pkg/cmd/util/clientcmd"
	dockerutil "github.com/openshift/origin/pkg/cmd/util/docker"
)

const (
	// CmdOnlineUpRecommendedName is the recommended command name
	CmdOnlineUpRecommendedName = "onlineup"

	openShiftOnlineContainer = "origin"
	openShiftOnlineNamespace = "openshift"

	initialOnlineUser     = "developer"
	initialOnlinePassword = "developer"

	initialOnlineProjectName    = "myproject"
	initialOnlineProjectDisplay = "My Project"
	initialOnlineProjectDesc    = "Initial developer project"

	defaultOnlineImages         = "openshift/origin-${component}:${version}"
	defaultOpenShiftOnlineImage = "openshift/origin:${version}"

	cmdOnlineUpLong = `
Starts an OpenShift cluster using Docker containers, provisioning a registry, router,
initial templates, and a default project.

This command will attempt to use an existing connection to a Docker daemon. Before running
the command, ensure that you can execure docker commands successfully (ie. 'docker ps').

Optionally, the command can create a new Docker machine for OpenShift using the VirtualBox
driver when the --create-machine argument is specified. The machine will be named 'openshift'
by default. To name the machine differently, use the --docker-machine=NAME argument. If the
--docker-machine=NAME argument is specified, but --create-machine is not, the command will attempt
to find an existing docker machine with that name and start it if it's not running.

By default, the OpenShift cluster will be setup to use a routing suffix that ends in xip.io.
This is to allow dynamic host names to be created for routes. An alternate routing suffix
can be specified using the --routing-suffix flag.

A public hostname can also be specified for the server with the --public-hostname flag.
`
	cmdOnlineUpExample = `
  # Start OpenShift on a new docker machine named 'openshift'
  %[1]s --create-machine

  # Start OpenShift using a specific public host name
  %[1]s --public-hostname=my.address.example.com

  # Start OpenShift and preserve data and config between restarts
  %[1]s --host-data-dir=/mydata --use-existing-config

  # Use a different set of images
  %[1]s --image="registry.example.com/origin" --version="v1.1"
`
)

var (
	OnlineImageStreamLocations = map[string]string{
		"origin centos7 image streams": "examples/image-streams/image-streams-centos7.json",
	}
	OnlineTemplateLocations = map[string]string{
		"mongodb":            "examples/db-templates/mongodb-ephemeral-template.json",
		"mysql":              "examples/db-templates/mysql-ephemeral-template.json",
		"postgresql":         "examples/db-templates/postgresql-ephemeral-template.json",
		"cakephp quickstart": "examples/quickstarts/cakephp-mysql.json",
		"dancer quickstart":  "examples/quickstarts/dancer-mysql.json",
		"django quickstart":  "examples/quickstarts/django-postgresql.json",
		"nodejs quickstart":  "examples/quickstarts/nodejs-mongodb.json",
		"rails quickstart":   "examples/quickstarts/rails-postgresql.json",
		"jenkins pipeline":   "examples/jenkins/pipeline/jenkinstemplate.json",
		"sample pipeline":    "examples/jenkins/pipeline/samplepipeline.json",
	}
)

// NewCmdOnlineUp creates a command that starts openshift on Docker with reasonable defaults
func NewCmdOnlineUp(name, fullName string, f *osclientcmd.Factory, out io.Writer) *cobra.Command {
	onlineconfig := &ClientOnlineStartConfig{
		Out: out,
	}
	cmd := &cobra.Command{
		Use:     name,
		Short:   "Start OpenShift on Docker with reasonable defaults",
		Long:    cmdOnlineUpLong,
		Example: fmt.Sprintf(cmdOnlineUpExample, fullName),
		Run: func(c *cobra.Command, args []string) {
			kcmdutil.CheckErr(onlineconfig.OnlineComplete(f, c))
			kcmdutil.CheckErr(onlineconfig.OnlineValidate(out))
			if err := onlineconfig.OnlineStart(out); err != nil {
				os.Exit(1)
			}
		},
	}
	cmd.Flags().BoolVar(&onlineconfig.ShouldCreateDockerMachine, "create-machine", false, "Create a Docker machine if one doesn't exist")
	cmd.Flags().StringVar(&onlineconfig.DockerMachine, "docker-machine", "", "Specify the Docker machine to use")
	cmd.Flags().StringVar(&onlineconfig.ImageVersion, "version", "latest", "Specify the tag for OpenShift images")
	cmd.Flags().StringVar(&onlineconfig.Image, "image", "openshift/origin", "Specify the images to use for OpenShift")
	cmd.Flags().BoolVar(&onlineconfig.SkipRegistryCheck, "skip-registry-check", false, "Skip Docker daemon registry check")
	cmd.Flags().StringVar(&onlineconfig.PublicHostname, "public-hostname", "", "Public hostname for OpenShift cluster")
	cmd.Flags().StringVar(&onlineconfig.RoutingSuffix, "routing-suffix", "", "Default suffix for server routes")
	cmd.Flags().BoolVar(&onlineconfig.UseExistingConfig, "use-existing-config", false, "Use existing configuration if present")
	cmd.Flags().StringVar(&onlineconfig.HostConfigDir, "host-config-dir", "/var/lib/origin/openshift.local.config", "Directory on Docker host for OpenShift configuration")
	cmd.Flags().StringVar(&onlineconfig.HostVolumesDir, "host-volumes-dir", "/var/lib/origin/openshift.local.volumes", "Directory on Docker host for OpenShift volumes")
	cmd.Flags().StringVar(&onlineconfig.HostDataDir, "host-data-dir", "", "Directory on Docker host for OpenShift data. If not specified, etcd data will not be persisted on the host.")
	cmd.Flags().IntVar(&onlineconfig.ServerLogLevel, "server-loglevel", 0, "Log level for OpenShift server")
	cmd.Flags().StringSliceVarP(&onlineconfig.Environment, "env", "e", onlineconfig.Environment, "Specify key value pairs of environment variables to set on OpenShift container")
	cmd.Flags().BoolVar(&onlineconfig.ShouldInstallOnlineMetrics, "metrics", false, "Install metrics (experimental)")
	return cmd
}

// onlineTaskFunc is a function that executes a start task
type onlineTaskFunc func(io.Writer) error

// onlinetask is a named task for the start process
type onlinetask struct {
	name string
	fn   onlineTaskFunc
}

// ClientStartConfig is the configuration for the client start command
type ClientOnlineStartConfig struct {
	ImageVersion               string
	Image                      string
	DockerMachine              string
	ShouldCreateDockerMachine  bool
	SkipRegistryCheck          bool
	ShouldInstallOnlineMetrics bool
	PortForwarding             bool

	UseNsenterMount bool
	Out             io.Writer
	TaskPrinter     *TaskPrinter
	Tasks           []onlinetask
	HostName        string
	ServerIP        string
	CACert          string
	PublicHostname  string
	RoutingSuffix   string
	DNSPort         int

	LocalConfigDir    string
	HostVolumesDir    string
	HostConfigDir     string
	HostDataDir       string
	UseExistingConfig bool
	Environment       []string
	ServerLogLevel    int

	dockerClient    *docker.Client
	engineAPIClient *dockerclient.Client
	dockerHelper    *dockerhelper.Helper
	hostHelper      *host.HostHelper
	openShiftHelper *openshift.Helper
	factory         *clientcmd.Factory
	originalFactory *clientcmd.Factory
	command         *cobra.Command

	usingDefaultImages         bool
	usingDefaultOpenShiftImage bool
}

func (c *ClientOnlineStartConfig) addOnlineTask(name string, fn onlineTaskFunc) {
	c.Tasks = append(c.Tasks, onlinetask{name: name, fn: fn})
}

// OnlineComplete initializes fields in StartConfig based on command parameters
// and execution environment
func (c *ClientOnlineStartConfig) OnlineComplete(f *osclientcmd.Factory, cmd *cobra.Command) error {
	c.TaskPrinter = NewTaskPrinter(c.Out)
	c.originalFactory = f
	c.command = cmd

	c.addOnlineTask("Checking OpenShift client", c.CheckOpenShiftClient)

	if c.ShouldCreateDockerMachine {
		// Create a Docker machine first if flag specified
		c.addOnlineTask("Create Docker machine", c.CreateOnlineDockerMachine)
	}
	// Get a Docker client.
	// If a Docker machine was specified, make sure that the machine is
	// running. Otherwise, use environment variables.
	c.addOnlineTask("Checking Docker client", c.GetOnlineDockerClient)

	// Check for an OpenShift container. If one exists and is running, exit.
	// If one exists but not running, delete it.
	c.addOnlineTask("Checking for existing OpenShift container", c.CheckExistingOnlineOpenShiftContainer)

	// Ensure that the OpenShift Docker image is available. If not present,
	// pull it.
	c.addOnlineTask(fmt.Sprintf("Checking for %s image", c.openShiftOnlineImage()), c.CheckOnlineOpenShiftImage)

	// Ensure that the Docker daemon has the right --insecure-registry argument. If
	// not, then exit.
	if !c.SkipRegistryCheck {
		c.addOnlineTask("Checking Docker daemon configuration", c.CheckOnlineDockerInsecureRegistry)
	}

	// Ensure that ports used by OpenShift are available on the host machine
	c.addOnlineTask("Checking for available ports", c.CheckOnlineAvailablePorts)

	// Check whether the Docker host has the right binaries to use Kubernetes' nsenter mounter
	// If not, use a shared volume to mount volumes on OpenShift
	c.addOnlineTask("Checking type of volume mount", c.CheckOnlineNsenterMounter)

	// Check that we have the minimum Docker version available to run OpenShift
	c.addOnlineTask("Checking Docker version", c.CheckOnlineDockerVersion)

	// If not using the nsenter mounter, create a volume share on the host machine to
	// mount OpenShift volumes.
	c.addOnlineTask("Creating volume share", c.EnsureVolumeShare)

	// Determine an IP to use for OpenShift. Uses the following sources:
	// - Docker host
	// - openshift start --print-ip
	// - hostname -I
	// Each IP is tested to ensure that it can be accessed from the current client
	c.addOnlineTask("Finding server IP", c.DetermineServerIP)

	// Create an OpenShift configuration and start a container that uses it.
	c.addOnlineTask("Starting OpenShift container", c.StartOpenShiftOnline)

	// Install a registry
	c.addOnlineTask("Installing registry", c.InstallOnlineRegistry)

	// Install a router
	c.addOnlineTask("Installing router", c.InstallOnlineRouter)

	// Install metrics
	if c.ShouldInstallOnlineMetrics {
		c.addOnlineTask("Install Metrics", c.InstallOnlineMetrics)
	}

	// Import default image streams
	c.addOnlineTask("Importing image streams", c.ImportImageStreams)

	// Import templates
	c.addOnlineTask("Importing templates", c.ImportTemplates)

	// Login with an initial default user
	c.addOnlineTask("Login to server", c.Login)

	// Create an initial project
	c.addOnlineTask(fmt.Sprintf("Creating initial project %q", initialOnlineProjectName), c.CreateProject)

	// Display server information
	c.addOnlineTask("Server Information", c.OnlineServerInfo)

	return nil
}

// OnlineValidate validates that required fields in StartConfig have been populated
func (c *ClientOnlineStartConfig) OnlineValidate(out io.Writer) error {
	if len(c.Tasks) == 0 {
		return fmt.Errorf("no startup tasks to execute")
	}
	return nil
}

// OnlineStart runs the start tasks ensuring that they are executed in sequence
func (c *ClientOnlineStartConfig) OnlineStart(out io.Writer) error {
	for _, onlinetask := range c.Tasks {
		c.TaskPrinter.StartTask(onlinetask.name)
		w := c.TaskPrinter.TaskWriter()
		err := onlinetask.fn(w)
		if err != nil {
			c.TaskPrinter.Failure(err)
			return err
		}
		c.TaskPrinter.Success()
	}
	return nil
}

const defaultOnlineDockerMachineName = "openshift"

// CreateOnlineDockerMachine will create a new Docker machine to run OpenShift
func (c *ClientOnlineStartConfig) CreateOnlineDockerMachine(out io.Writer) error {
	if len(c.DockerMachine) == 0 {
		c.DockerMachine = defaultOnlineDockerMachineName
	}
	fmt.Fprintf(out, "Creating docker-machine %s\n", c.DockerMachine)
	return dockermachine.NewBuilder().Name(c.DockerMachine).Create()
}

// CheckOpenShiftClient ensures that the client can be configured
// for the new server
func (c *ClientOnlineStartConfig) CheckOpenShiftClient(out io.Writer) error {
	kubeConfig := os.Getenv("KUBECONFIG")
	if len(kubeConfig) == 0 {
		return nil
	}
	var (
		kubeConfigError error
		f               *os.File
	)
	_, err := os.Stat(kubeConfig)
	switch {
	case os.IsNotExist(err):
		err = os.MkdirAll(filepath.Dir(kubeConfig), 0755)
		if err != nil {
			kubeConfigError = fmt.Errorf("cannot make directory: %v", err)
			break
		}
		f, err = os.Create(kubeConfig)
		if err != nil {
			kubeConfigError = fmt.Errorf("cannot create file: %v", err)
			break
		}
		f.Close()
	case err == nil:
		f, err = os.OpenFile(kubeConfig, os.O_RDWR, 0644)
		if err != nil {
			kubeConfigError = fmt.Errorf("cannot open %s for write: %v", kubeConfig, err)
			break
		}
		f.Close()
	default:
		kubeConfigError = fmt.Errorf("cannot access %s: %v", kubeConfig, err)
	}
	if kubeConfigError != nil {
		return errors.ErrKubeConfigNotWriteable(kubeConfig, kubeConfigError)
	}
	return nil
}

// GetOnlineDockerClient will obtain a new Docker client from the environment or
// from a Docker machine, starting it if necessary
func (c *ClientOnlineStartConfig) GetOnlineDockerClient(out io.Writer) error {
	var err error

	if len(c.DockerMachine) > 0 {
		glog.V(2).Infof("Getting client for Docker machine %q", c.DockerMachine)
		c.dockerClient, c.engineAPIClient, err = getOnlineDockerMachineClient(c.DockerMachine, out)
		if err != nil {
			return errors.ErrNoDockerMachineClient(c.DockerMachine, err)
		}
		return nil
	}

	if glog.V(4) {
		dockerHost := os.Getenv("DOCKER_HOST")
		dockerTLSVerify := os.Getenv("DOCKER_TLS_VERIFY")
		dockerCertPath := os.Getenv("DOCKER_CERT_PATH")
		if len(dockerHost) == 0 && len(dockerTLSVerify) == 0 && len(dockerCertPath) == 0 {
			glog.Infof("No Docker environment variables found. Will attempt default socket.")
		}
		if len(dockerHost) > 0 {
			glog.Infof("Will try Docker connection with host (DOCKER_HOST) %q", dockerHost)
		} else {
			glog.Infof("No Docker host (DOCKER_HOST) configured. Will attempt default socket.")
		}
		if len(dockerTLSVerify) > 0 {
			glog.Infof("DOCKER_TLS_VERIFY=%s", dockerTLSVerify)
		}
		if len(dockerCertPath) > 0 {
			glog.Infof("DOCKER_CERT_PATH=%s", dockerCertPath)
		}
	}
	c.dockerClient, _, err = dockerutil.NewHelper().GetClient()
	if err != nil {
		return errors.ErrNoDockerClient(err)
	}
	// FIXME: Workaround for docker engine API client on OS X - sets the default to
	// the wrong DOCKER_HOST string
	if runtime.GOOS == "darwin" {
		dockerHost := os.Getenv("DOCKER_HOST")
		if len(dockerHost) == 0 {
			os.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
		}
	}
	c.engineAPIClient, err = dockerclient.NewEnvClient()
	if err != nil {
		return errors.ErrNoDockerClient(err)
	}
	if err = c.dockerClient.Ping(); err != nil {
		return errors.ErrCannotPingDocker(err)
	}
	glog.V(4).Infof("Docker ping succeeded")
	return nil
}

// CheckExistingOnlineOpenShiftContainer checks the state of an OpenShift container. If one
// is already running, it throws an error. If one exists, it removes it so a new one
// can be created.
func (c *ClientOnlineStartConfig) CheckExistingOnlineOpenShiftContainer(out io.Writer) error {
	exists, running, err := c.DockerHelper().GetContainerState(openShiftOnlineContainer)
	if err != nil {
		return errors.NewError("unexpected error while checking OpenShift container state").WithCause(err)
	}
	if running {
		return errors.NewError("OpenShift is already running").WithSolution("To start OpenShift again, stop current %q container.", openShiftOnlineContainer)
	}
	if exists {
		err = c.DockerHelper().RemoveContainer(openShiftOnlineContainer)
		if err != nil {
			return errors.NewError("cannot delete existing OpenShift container").WithCause(err)
		}
		fmt.Fprintf(out, "Deleted existing OpenShift container\n")
	}
	return nil
}

// CheckOpenShiftImage checks whether the OpenShift image exists. If not it tells the
// Docker daemon to pull it.
func (c *ClientOnlineStartConfig) CheckOnlineOpenShiftImage(out io.Writer) error {
	return c.DockerHelper().CheckAndPull(c.openShiftOnlineImage(), out)
}

// CheckDockerInsecureRegistry checks whether the Docker daemon is using the right --insecure-registry argument
func (c *ClientOnlineStartConfig) CheckOnlineDockerInsecureRegistry(out io.Writer) error {
	hasArg, err := c.DockerHelper().HasInsecureRegistryArg()
	if err != nil {
		return err
	}
	if !hasArg {
		return errors.ErrNoInsecureRegistryArgument()
	}
	return nil
}

// CheckNsenterMounter checks whether the Docker host can use the nsenter mounter from Kubernetes. Otherwise,
// a shared volume is needed in Docker
func (c *ClientOnlineStartConfig) CheckOnlineNsenterMounter(out io.Writer) error {
	var err error
	c.UseNsenterMount, err = c.HostHelper().CanUseNsenterMounter()
	if c.UseNsenterMount {
		fmt.Fprintf(out, "Using nsenter mounter for OpenShift volumes\n")
	} else {
		fmt.Fprintf(out, "Using Docker shared volumes for OpenShift volumes\n")
	}
	return err
}

// CheckDockerVersion checks that the appropriate Docker version is installed based on whether we are using the nsenter mounter
// or shared volumes for OpenShift
func (c *ClientOnlineStartConfig) CheckOnlineDockerVersion(io.Writer) error {
	var minDockerVersion semver.Version
	if c.UseNsenterMount {
		minDockerVersion = semver.MustParse("1.8.1")
	} else {
		minDockerVersion = semver.MustParse("1.10.0")
	}
	ver, err := c.DockerHelper().Version()
	if err != nil {
		return err
	}
	glog.V(5).Infof("Checking that docker version is at least %v", minDockerVersion)
	if ver.LT(minDockerVersion) {
		return fmt.Errorf("Docker version is %v, it needs to be %v", ver, minDockerVersion)
	}
	return nil
}

// EnsureVolumeShare ensures that a volume share exists on the Docker host machine if
// not using the nsenter mounter for the OpenShift node
func (c *ClientOnlineStartConfig) EnsureVolumeShare(io.Writer) error {
	// A host volume share is not needed if using the nsenter mounter
	if c.UseNsenterMount {
		glog.V(5).Infof("Volume share is not needed when using nsenter mounter.")
		return nil
	}
	return c.HostHelper().EnsureVolumeShare()
}

// CheckOnlineAvailablePorts ensures that ports used by OpenShift are available on the Docker host
func (c *ClientOnlineStartConfig) CheckOnlineAvailablePorts(out io.Writer) error {
	err := c.OpenShiftHelper().TestPorts(openshift.DefaultPorts)
	if err == nil {
		c.DNSPort = openshift.DefaultDNSPort
		return nil
	}
	if !openshift.IsPortsNotAvailableErr(err) {
		return err
	}
	conflicts := openshift.UnavailablePorts(err)
	if len(conflicts) == 1 && conflicts[0] == openshift.DefaultDNSPort {
		err = c.OpenShiftHelper().TestPorts(openshift.PortsWithAlternateDNS)
		if err == nil {
			c.DNSPort = openshift.AlternateDNSPort
			fmt.Fprintf(out, "WARNING: Binding DNS on port %d instead of 53, which may be not be resolvable from all clients.\n", openshift.AlternateDNSPort)
			return nil
		}
	}
	return errors.NewError("a port needed by OpenShift is not available").WithCause(err)
}

// DetermineServerIP gets an appropriate IP address to communicate with the OpenShift server
func (c *ClientOnlineStartConfig) DetermineServerIP(out io.Writer) error {
	ip, err := c.determineIP(out)
	if err != nil {
		return errors.NewError("cannot determine a server IP to use").WithCause(err)
	}
	c.ServerIP = ip
	fmt.Fprintf(out, "Using %s as the server IP\n", ip)
	return nil
}

// StartOpenShiftOnline starts the OpenShift container
func (c *ClientOnlineStartConfig) StartOpenShiftOnline(out io.Writer) error {
	var err error
	opt := &openshift.StartOptions{
		ServerIP:          c.ServerIP,
		UseSharedVolume:   !c.UseNsenterMount,
		Images:            c.OnlineImageFormat(),
		HostVolumesDir:    c.HostVolumesDir,
		HostConfigDir:     c.HostConfigDir,
		HostDataDir:       c.HostDataDir,
		UseExistingConfig: c.UseExistingConfig,
		Environment:       c.Environment,
		LogLevel:          c.ServerLogLevel,
		DNSPort:           c.DNSPort,
		PortForwarding:    c.PortForwarding,
	}
	if c.ShouldInstallOnlineMetrics {
		opt.MetricsHost = openshift.MetricsHost(c.RoutingSuffix, c.ServerIP)
	}
	c.LocalConfigDir, err = c.OpenShiftHelper().Start(opt, out)
	return err
}

func (c *ClientOnlineStartConfig) OnlineImageFormat() string {
	return fmt.Sprintf("%s-${component}:%s", c.Image, c.ImageVersion)
}

// InstallOnlineRegistry installs the OpenShift registry on the server
func (c *ClientOnlineStartConfig) InstallOnlineRegistry(out io.Writer) error {
	_, kubeClient, err := c.Clients()
	if err != nil {
		return err
	}
	f, err := c.Factory()
	if err != nil {
		return err
	}
	return c.OpenShiftHelper().InstallRegistry(kubeClient, f, c.LocalConfigDir, c.OnlineImageFormat(), out)
}

// InstallOnlineRouter installs a default router on the server
func (c *ClientOnlineStartConfig) InstallOnlineRouter(out io.Writer) error {
	_, kubeClient, err := c.Clients()
	if err != nil {
		return err
	}
	f, err := c.Factory()
	if err != nil {
		return err
	}
	return c.OpenShiftHelper().InstallRouter(kubeClient, f, c.LocalConfigDir, c.OnlineImageFormat(), c.ServerIP, c.PortForwarding, out)
}

// ImportImageStreams imports default image streams into the server
// TODO: Use streams compiled into oc
func (c *ClientOnlineStartConfig) ImportImageStreams(out io.Writer) error {
	return c.importObjects(out, OnlineImageStreamLocations)
}

// ImportTemplates imports default templates into the server
// TODO: Use templates compiled into oc
func (c *ClientOnlineStartConfig) ImportTemplates(out io.Writer) error {
	return c.importObjects(out, templateLocations)
}

/*
// TODO: implement this
func (c *ClientStartConfig) InstallLogging() error {
	return nil
}
*/

func (c *ClientOnlineStartConfig) InstallOnlineMetrics(out io.Writer) error {
	f, err := c.Factory()
	if err != nil {
		return err
	}
	return c.OpenShiftHelper().InstallMetrics(f, openshift.MetricsHost(c.RoutingSuffix, c.ServerIP), c.Image, c.ImageVersion)
}

// Login logs into the new server and sets up a default user and project
func (c *ClientOnlineStartConfig) Login(out io.Writer) error {
	server := c.OpenShiftHelper().Master(c.ServerIP)
	return openshift.Login(initialOnlineUser, initialOnlinePassword, server, c.LocalConfigDir, c.originalFactory, c.command, out)
}

// CreateProject creates a new project for the current user
func (c *ClientOnlineStartConfig) CreateProject(out io.Writer) error {
	return openshift.CreateProject(initialOnlineProjectName, initialOnlineProjectDisplay, initialOnlineProjectDesc, "oc", out)

}

// OnlineOnlineServerInfo displays server information after a successful start
func (c *ClientOnlineStartConfig) OnlineServerInfo(out io.Writer) error {
	metricsInfo := ""
	if c.ShouldInstallOnlineMetrics {
		metricsInfo = fmt.Sprintf("The metrics service is available at:\n"+
			"    https://%s\n\n", openshift.MetricsHost(c.RoutingSuffix, c.ServerIP))
	}
	fmt.Fprintf(out, "OpenShift server started.\n"+
		"The server is accessible via web console at:\n"+
		"    %s\n\n%s"+
		"You are logged in as:\n"+
		"    User:     %s\n"+
		"    Password: %s\n\n"+
		"To login as administrator:\n"+
		"    oc login -u system:admin\n\n",
		c.OpenShiftHelper().Master(c.ServerIP),
		metricsInfo,
		initialOnlineUser,
		initialOnlinePassword)
	return nil
}

// Factory returns a command factory that works with OpenShift server's admin credentials
func (c *ClientOnlineStartConfig) Factory() (*clientcmd.Factory, error) {
	if c.factory == nil {
		cfg, err := kclientcmd.LoadFromFile(filepath.Join(c.LocalConfigDir, "master", "admin.kubeconfig"))
		if err != nil {
			return nil, err
		}
		defaultCfg := kclientcmd.NewDefaultClientConfig(*cfg, &kclientcmd.ConfigOverrides{})
		c.factory = clientcmd.NewFactory(defaultCfg)
	}
	return c.factory, nil
}

// Clients returns clients for OpenShift and Kube
func (c *ClientOnlineStartConfig) Clients() (*client.Client, *kclient.Client, error) {
	f, err := c.Factory()
	if err != nil {
		return nil, nil, err
	}
	return f.Clients()
}

// OpenShiftHelper returns a helper object to work with OpenShift on the server
func (c *ClientOnlineStartConfig) OpenShiftHelper() *openshift.Helper {
	if c.openShiftHelper == nil {
		c.openShiftHelper = openshift.NewHelper(c.dockerClient, c.HostHelper(), c.openShiftOnlineImage(), openShiftOnlineContainer, c.PublicHostname, c.RoutingSuffix)
	}
	return c.openShiftHelper
}

// HostHelper returns a helper object to check Host configuration
func (c *ClientOnlineStartConfig) HostHelper() *host.HostHelper {
	if c.hostHelper == nil {
		c.hostHelper = host.NewHostHelper(c.dockerClient, c.openShiftOnlineImage(), c.HostVolumesDir, c.HostConfigDir, c.HostDataDir)
	}
	return c.hostHelper
}

// DockerHelper returns a helper object to work with the Docker client
func (c *ClientOnlineStartConfig) DockerHelper() *dockerhelper.Helper {
	if c.dockerHelper == nil {
		c.dockerHelper = dockerhelper.NewHelper(c.dockerClient, c.engineAPIClient)
	}
	return c.dockerHelper
}

func (c *ClientOnlineStartConfig) importObjects(out io.Writer, locations map[string]string) error {
	f, err := c.Factory()
	if err != nil {
		return err
	}
	for name, location := range locations {
		glog.V(2).Infof("Importing %s from %s", name, location)
		err = openshift.ImportObjects(f, openShiftOnlineNamespace, location)
		if err != nil {
			return errors.NewError("cannot import %s", name).WithCause(err).WithDetails(c.OpenShiftHelper().OriginLog())
		}
	}
	return nil
}

func (c *ClientOnlineStartConfig) openShiftOnlineImage() string {
	return fmt.Sprintf("%s:%s", c.Image, c.ImageVersion)
}

func getOnlineDockerMachineClient(machine string, out io.Writer) (*docker.Client, *dockerclient.Client, error) {
	if !dockermachine.IsRunning(machine) {
		fmt.Fprintf(out, "Starting Docker machine '%s'\n", machine)
		err := dockermachine.Start(machine)
		if err != nil {
			return nil, nil, errors.NewError("cannot start Docker machine %q", machine).WithCause(err)
		}
		fmt.Fprintf(out, "Started Docker machine '%s'\n", machine)
	}
	return dockermachine.Client(machine)
}

func (c *ClientOnlineStartConfig) determineIP(out io.Writer) (string, error) {
	if ip := net.ParseIP(c.PublicHostname); ip != nil && !ip.IsUnspecified() {
		fmt.Fprintf(out, "Using public hostname IP %s as the host IP\n", ip)
		return ip.String(), nil
	}

	if len(c.DockerMachine) > 0 {
		glog.V(2).Infof("Using docker machine %q to determine server IP", c.DockerMachine)
		ip, err := dockermachine.IP(c.DockerMachine)
		if err != nil {
			return "", errors.NewError("Could not determine IP address").WithCause(err).WithSolution("Ensure that docker-machine is functional.")
		}
		fmt.Fprintf(out, "Using docker-machine IP %s as the host IP\n", ip)
		return ip, nil
	}

	// First, try to get the host from the DOCKER_HOST if communicating via tcp
	var err error
	ip := c.DockerHelper().HostIP()
	if ip != "" {
		glog.V(2).Infof("Testing Docker host IP (%s)", ip)
		if err = c.OpenShiftHelper().TestIP(ip); err == nil {
			return ip, nil
		}
	}
	glog.V(2).Infof("Cannot use the Docker host IP(%s): %v", ip, err)

	// Next, use the the --print-ip output from openshift
	ip, err = c.OpenShiftHelper().ServerIP()
	if err == nil {
		glog.V(2).Infof("Testing openshift --print-ip (%s)", ip)
		if err = c.OpenShiftHelper().TestIP(ip); err == nil {
			return ip, nil
		}
		glog.V(2).Infof("OpenShift server ip test failed: %v", err)
	}
	glog.V(2).Infof("Cannot use OpenShift IP: %v", err)

	// Next, try other IPs on Docker host
	ips, err := c.OpenShiftHelper().OtherIPs(ip)
	if err != nil {
		return "", err
	}
	for i := range ips {
		glog.V(2).Infof("Testing additional IP (%s)", ip)
		if err = c.OpenShiftHelper().TestIP(ips[i]); err == nil {
			return ip, nil
		}
		glog.V(2).Infof("OpenShift additional ip test failed: %v", err)
	}
	return "", errors.NewError("cannot determine an IP to use for your server.")
}
