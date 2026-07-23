package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func main() {
	registryId := flag.String("registryId", "", "RegistryId")
	roleArn := flag.String("roleArn", "", "RoleArn")
	externalId := flag.String("externalId", "", "ExternalId")
	region := flag.String("region", "", "Region")

	flag.Parse()

	ctx := context.Background()

	cfg, err := getAssumedConfig(ctx, *roleArn, *externalId, *region)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	token, err := getEcrToken(ctx, cfg, *registryId)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("%s", token)
}

func getAssumedConfig(ctx context.Context, roleArn, externalId, region string) (aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return aws.Config{}, err
	}

	stsClient := sts.NewFromConfig(cfg)
	sessionName := fmt.Sprintf("spinnakerManagedEcr-%d", rand.Int())

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(sessionName),
	}
	if externalId != "" {
		input.ExternalId = aws.String(externalId)
	}

	assumedRole, err := stsClient.AssumeRole(ctx, input)
	if err != nil {
		return aws.Config{}, err
	}

	return config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			*assumedRole.Credentials.AccessKeyId,
			*assumedRole.Credentials.SecretAccessKey,
			*assumedRole.Credentials.SessionToken,
		)),
	)
}

func getEcrToken(ctx context.Context, cfg aws.Config, registry string) (string, error) {
	ecrClient := ecr.NewFromConfig(cfg)

	authOutput, err := ecrClient.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{
		RegistryIds: []string{registry},
	})
	if err != nil {
		return "", err
	}

	for _, data := range authOutput.AuthorizationData {
		decoded, err := base64.StdEncoding.DecodeString(*data.AuthorizationToken)
		if err != nil {
			return "", err
		}
		parts := strings.Split(string(decoded), ":")
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1]), nil
		}
		return "", fmt.Errorf("failed to parse token")
	}
	return "", fmt.Errorf("password was empty")
}
