// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credentiallibraries

import (
	"strings"

	"github.com/hashicorp/boundary/api"
)

// Option is a func that sets optional attributes for a call. This does not need
// to be used directly, but instead option arguments are built from the
// functions in this package. WithX options set a value to that given in the
// argument; DefaultX options indicate that the value should be set to its
// default. When an API call is made options are processed in ther order they
// appear in the function call, so for a given argument X, a succession of WithX
// or DefaultX calls will result in the last call taking effect.
type Option func(*options)

type options struct {
	postMap                 map[string]interface{}
	queryMap                map[string]string
	withAutomaticVersioning bool
	withSkipCurlOutput      bool
	withFilter              string
}

func getDefaultOptions() options {
	return options{
		postMap:  make(map[string]interface{}),
		queryMap: make(map[string]string),
	}
}

func getOpts(opt ...Option) (options, []api.Option) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	var apiOpts []api.Option
	if opts.withSkipCurlOutput {
		apiOpts = append(apiOpts, api.WithSkipCurlOutput(true))
	}
	if opts.withFilter != "" {
		opts.queryMap["filter"] = opts.withFilter
	}
	return opts, apiOpts
}

// If set, and if the version is zero during an update, the API will perform a
// fetch to get the current version of the resource and populate it during the
// update call. This is convenient but opens up the possibility for subtle
// order-of-modification issues, so use carefully.
func WithAutomaticVersioning(enable bool) Option {
	return func(o *options) {
		o.withAutomaticVersioning = enable
	}
}

// WithSkipCurlOutput tells the API to not use the current call for cURL output.
// Useful for when we need to look up versions.
func WithSkipCurlOutput(skip bool) Option {
	return func(o *options) {
		o.withSkipCurlOutput = true
	}
}

// WithFilter tells the API to filter the items returned using the provided
// filter term.  The filter should be in a format supported by
// hashicorp/go-bexpr.
func WithFilter(filter string) Option {
	return func(o *options) {
		o.withFilter = strings.TrimSpace(filter)
	}
}

func WithAttributes(inAttributes map[string]interface{}) Option {
	return func(o *options) {
		o.postMap["attributes"] = inAttributes
	}
}

func DefaultAttributes() Option {
	return func(o *options) {
		o.postMap["attributes"] = nil
	}
}

func WithCredentialMappingOverrides(inCredentialMappingOverrides map[string]interface{}) Option {
	return func(o *options) {
		o.postMap["credential_mapping_overrides"] = inCredentialMappingOverrides
	}
}

func DefaultCredentialMappingOverrides() Option {
	return func(o *options) {
		o.postMap["credential_mapping_overrides"] = nil
	}
}

func WithCredentialType(inCredentialType string) Option {
	return func(o *options) {
		o.postMap["credential_type"] = inCredentialType
	}
}

func DefaultCredentialType() Option {
	return func(o *options) {
		o.postMap["credential_type"] = nil
	}
}

func WithVaultSSHCertificateCredentialLibraryCriticalOptions(inCriticalOptions map[string]string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["critical_options"] = inCriticalOptions
		o.postMap["attributes"] = val
	}
}

func DefaultVaultSSHCertificateCredentialLibraryCriticalOptions() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["critical_options"] = nil
		o.postMap["attributes"] = val
	}
}

func WithDescription(inDescription string) Option {
	return func(o *options) {
		o.postMap["description"] = inDescription
	}
}

func DefaultDescription() Option {
	return func(o *options) {
		o.postMap["description"] = nil
	}
}

func WithVaultSSHCertificateCredentialLibraryExtensions(inExtensions map[string]string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["extensions"] = inExtensions
		o.postMap["attributes"] = val
	}
}

func DefaultVaultSSHCertificateCredentialLibraryExtensions() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["extensions"] = nil
		o.postMap["attributes"] = val
	}
}

func WithVaultCredentialLibraryHttpMethod(inHttpMethod string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["http_method"] = inHttpMethod
		o.postMap["attributes"] = val
	}
}

func DefaultVaultCredentialLibraryHttpMethod() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["http_method"] = nil
		o.postMap["attributes"] = val
	}
}

func WithVaultCredentialLibraryHttpRequestBody(inHttpRequestBody string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["http_request_body"] = inHttpRequestBody
		o.postMap["attributes"] = val
	}
}

func DefaultVaultCredentialLibraryHttpRequestBody() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["http_request_body"] = nil
		o.postMap["attributes"] = val
	}
}

func WithVaultSSHCertificateCredentialLibraryKeyBits(inKeyBits uint32) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["key_bits"] = inKeyBits
		o.postMap["attributes"] = val
	}
}

func DefaultVaultSSHCertificateCredentialLibraryKeyBits() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["key_bits"] = nil
		o.postMap["attributes"] = val
	}
}

func WithVaultSSHCertificateCredentialLibraryKeyId(inKeyId string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["key_id"] = inKeyId
		o.postMap["attributes"] = val
	}
}

func DefaultVaultSSHCertificateCredentialLibraryKeyId() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["key_id"] = nil
		o.postMap["attributes"] = val
	}
}

func WithVaultSSHCertificateCredentialLibraryKeyType(inKeyType string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["key_type"] = inKeyType
		o.postMap["attributes"] = val
	}
}

func DefaultVaultSSHCertificateCredentialLibraryKeyType() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["key_type"] = nil
		o.postMap["attributes"] = val
	}
}

func WithName(inName string) Option {
	return func(o *options) {
		o.postMap["name"] = inName
	}
}

func DefaultName() Option {
	return func(o *options) {
		o.postMap["name"] = nil
	}
}

func WithVaultCredentialLibraryPath(inPath string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["path"] = inPath
		o.postMap["attributes"] = val
	}
}

func WithVaultSSHCertificateCredentialLibraryPath(inPath string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["path"] = inPath
		o.postMap["attributes"] = val
	}
}

func WithVaultSSHCertificateCredentialLibraryTtl(inTtl string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["ttl"] = inTtl
		o.postMap["attributes"] = val
	}
}

func DefaultVaultSSHCertificateCredentialLibraryTtl() Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["ttl"] = nil
		o.postMap["attributes"] = val
	}
}

func WithVaultSSHCertificateCredentialLibraryUsername(inUsername string) Option {
	return func(o *options) {
		raw, ok := o.postMap["attributes"]
		if !ok {
			raw = interface{}(map[string]interface{}{})
		}
		val := raw.(map[string]interface{})
		val["username"] = inUsername
		o.postMap["attributes"] = val
	}
}
