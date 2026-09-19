package oidc

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/oauth2"
)

// DeviceFlow drives the OAuth 2.0 device authorization grant, the flow a
// headless client uses to obtain an ID token.
type DeviceFlow struct {
	oauth *oauth2.Config
	// Prompt is called with the verification URI and user code. It defaults to
	// printing them so a terminal user can complete the flow elsewhere.
	Prompt func(verificationURI, userCode string)
}

// NewDeviceFlow performs discovery and prepares the device flow.
func NewDeviceFlow(ctx context.Context, config Config) (*DeviceFlow, error) {
	verifier, err := NewVerifier(ctx, config)
	if err != nil {
		return nil, err
	}
	authURL, tokenURL, deviceAuthURL := verifier.Endpoint()
	if deviceAuthURL == "" {
		return nil, fmt.Errorf("issuer %s does not advertise a device authorization endpoint", config.Issuer)
	}
	return &DeviceFlow{
		oauth: &oauth2.Config{
			ClientID: config.ClientID,
			Scopes:   config.ScopesOrDefault(),
			Endpoint: oauth2.Endpoint{AuthURL: authURL, TokenURL: tokenURL, DeviceAuthURL: deviceAuthURL},
		},
		Prompt: func(verificationURI, userCode string) {
			fmt.Fprintf(os.Stderr, "To authenticate, visit %s and enter code %s\n", verificationURI, userCode)
		},
	}, nil
}

// IDToken runs the grant to completion and returns the raw ID token.
func (flow *DeviceFlow) IDToken(ctx context.Context) (string, error) {
	response, err := flow.oauth.DeviceAuth(ctx)
	if err != nil {
		return "", fmt.Errorf("device authorization: %w", err)
	}
	if flow.Prompt != nil {
		flow.Prompt(response.VerificationURI, response.UserCode)
	}
	token, err := flow.oauth.DeviceAccessToken(ctx, response)
	if err != nil {
		return "", fmt.Errorf("device token: %w", err)
	}
	idToken, _ := token.Extra("id_token").(string)
	if idToken == "" {
		return "", fmt.Errorf("token response contained no id_token")
	}
	return idToken, nil
}
