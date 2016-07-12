package secrets

import (
	"errors"
	"fmt"
	"io"
	"strings"

	kapi "k8s.io/kubernetes/pkg/api"
	kcmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"

	"github.com/spf13/cobra"
)

const (
	AddSecretRecommendedName = "add"

	// TODO: move to examples
	addSecretLong = `
Add secrets to a ServiceAccount

After you have created a secret, you probably want to make use of that secret inside of a pod, for a build, or as an image pull secret.  In order to do that, you must add your secret to a service account.`

	addSecretExample = `  // To use your secret inside of a pod or as a push, pull, or source secret for a build, you must add a 'mount' secret to your service account like this:
  %[1]s serviceaccount/sa-name secrets/secret-name secrets/another-secret-name

  // To use your secret as an image pull secret, you must add a 'pull' secret to your service account like this:
  %[1]s serviceaccount/sa-name secrets/secret-name --for=pull

  // To use your secret for image pulls or inside a pod:
  %[1]s serviceaccount/sa-name secrets/secret-name --for=pull,mount`
)

type AddSecretOptions struct {
	SecretOptions

	ForMount bool
	ForPull  bool

	typeFlags []string
}

// NewCmdAddSecret creates a command object for adding a secret reference to a service account
func NewCmdAddSecret(name, fullName string, f *kcmdutil.Factory, out io.Writer) *cobra.Command {
	o := &AddSecretOptions{SecretOptions{Out: out}, false, false, nil}

	cmd := &cobra.Command{
		Use:     fmt.Sprintf("%s serviceaccounts/sa-name secrets/secret-name [secrets/another-secret-name]...", name),
		Short:   "Add secrets to a ServiceAccount",
		Long:    addSecretLong,
		Example: fmt.Sprintf(addSecretExample, fullName),
		Run: func(c *cobra.Command, args []string) {
			if err := o.Complete(f, args); err != nil {
				kcmdutil.CheckErr(kcmdutil.UsageError(c, err.Error()))
			}

			if err := o.Validate(); err != nil {
				kcmdutil.CheckErr(kcmdutil.UsageError(c, err.Error()))
			}

			if err := o.AddSecrets(); err != nil {
				kcmdutil.CheckErr(err)
			}

		},
	}

	cmd.Flags().StringSliceVar(&o.typeFlags, "for", []string{"mount"}, "type of secret to add: mount or pull")

	return cmd
}

func (o *AddSecretOptions) Complete(f *kcmdutil.Factory, args []string) error {
	if err := o.SecretOptions.Complete(f, args); err != nil {
		return err
	}

	if len(o.typeFlags) == 0 {
		o.ForMount = true
	} else {
		for _, flag := range o.typeFlags {
			loweredValue := strings.ToLower(flag)
			switch loweredValue {
			case "pull":
				o.ForPull = true
			case "mount":
				o.ForMount = true
			default:
				return fmt.Errorf("unknown for: %v", flag)
			}
		}
	}

	return nil
}

func (o AddSecretOptions) Validate() error {
	if err := o.SecretOptions.Validate(); err != nil {
		return err
	}

	if !o.ForPull && !o.ForMount {
		return errors.New("for must be present")
	}

	return nil
}

func (o AddSecretOptions) AddSecrets() error {
	serviceaccount, err := o.GetServiceAccount()
	if err != nil {
		return err
	}

	err = o.addSecretsToServiceAccount(serviceaccount)
	if err != nil {
		return err
	}

	return nil
}

// TODO: when Secrets in kapi.ServiceAccount get changed to MountSecrets and represented by LocalObjectReferences, this can be
// refactored to reuse the addition code better
// addSecretsToServiceAccount adds secrets to the service account, either as pull secrets, mount secrets, or both.
func (o AddSecretOptions) addSecretsToServiceAccount(serviceaccount *kapi.ServiceAccount) error {
	updated := false
	newSecrets, err := o.GetSecrets()
	if err != nil {
		return err
	}
	newSecretNames := o.GetSecretNames(newSecrets)

	if o.ForMount {
		currentSecrets := o.GetMountSecretNames(serviceaccount)
		secretsToAdd := newSecretNames.Difference(currentSecrets)
		for _, secretName := range secretsToAdd.List() {
			serviceaccount.Secrets = append(serviceaccount.Secrets, kapi.ObjectReference{Name: secretName})
			updated = true
		}
	}
	if o.ForPull {
		currentSecrets := o.GetPullSecretNames(serviceaccount)
		secretsToAdd := newSecretNames.Difference(currentSecrets)
		for _, secretName := range secretsToAdd.List() {
			serviceaccount.ImagePullSecrets = append(serviceaccount.ImagePullSecrets, kapi.LocalObjectReference{Name: secretName})
			updated = true
		}
	}
	if updated {
		_, err = o.ClientInterface.ServiceAccounts(o.Namespace).Update(serviceaccount)
		return err
	}
	return nil
}
