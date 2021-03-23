package authmethods

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/api/authtokens"
)

// AuthenticatePassword performs a password authentication flow, suitable for a
// Password-style auth method.
func (c *Client) AuthenticatePassword(ctx context.Context, authMethodId, loginName, password string, opt ...Option) (*authtokens.AuthTokenReadResult, error) {
	if c.client == nil {
		return nil, fmt.Errorf("nil client in AuthenticatePassword request")
	}

	_, apiOpts := getOpts(opt...)

	reqBody := map[string]interface{}{
		"login_name": loginName,
		"password":   password,
	}

	req, err := c.client.NewRequest(ctx, "POST", fmt.Sprintf("auth-methods/%s:authenticate:login", authMethodId), reqBody, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating AuthenticatePassword request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error performing client request during AuthenticatePassword call: %w", err)
	}

	target := new(authtokens.AuthTokenReadResult)
	target.Item = new(authtokens.AuthToken)
	apiErr, err := resp.Decode(target.Item)
	if err != nil {
		return nil, fmt.Errorf("error decoding AuthenticatePassword response: %w", err)
	}
	if apiErr != nil {
		return nil, apiErr
	}

	return target, nil
}
