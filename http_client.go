package tls_client

import (
	fhttp "github.com/bogdanfinn/fhttp"
)

// Expose the underlying *fhttp.Client from HttpClient
func (c *httpClient) GetUnderlyingClient() *fhttp.Client {
	return &c.Client // because fhttp.Client is embedded
}
