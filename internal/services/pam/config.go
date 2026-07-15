package pam

const (
	// SSHServiceName is the default PAM service name for sshd.
	SSHServiceName = "sshd"
)

type ConfigValues struct {
	DisableLocalStack bool `mapstructure:"disable_local_stack" yaml:"disable_local_stack"`
}

// Config is the configuration for the PAM service.
type Config struct {
	ConfigValues `mapstructure:",squash" yaml:",inline"`

	// TODO: Include here all the relevant PAM module `supportedArgs` values and
	// providing them to the client via a new GetConfig GRPC request, thus
	// only allow to override them from the PAM module side, since they may
	// be useful for debugging.

	// ServicesOverrides is a map containing the [ConfigValue] overrides for
	// specific services.
	ServicesOverrides map[string]ConfigValues `mapstructure:"services_overrides" yaml:"services_overrides"`
}

func (c Config) GetServiceConfigValues(serviceName string) ConfigValues {
	so, ok := c.ServicesOverrides[serviceName]
	if !ok {
		return c.ConfigValues
	}

	// FIXME: Use reflect to iterate over values when we'll have more...
	c.DisableLocalStack = so.DisableLocalStack
	return c.ConfigValues
}

// DefaultConfig is the default configuration for the PAM service.
var DefaultConfig = Config{
	ServicesOverrides: map[string]ConfigValues{SSHServiceName: {DisableLocalStack: true}},
}
