package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/sts"
	"math/rand"
	"os"
	"strings"
)

var token string

func main() {
	registryId := flag.String("registryId", "", "RegistryId")
	roleArn := flag.String("roleArn", "", "RoleArn")
	externalId := flag.String("externalId", "", "ExternalId")
	region := flag.String("region", "", "Region")

	flag.Parse()

	session, err := getAssumedSession(*roleArn, *externalId, *region)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	authToken, err := getEcrToken(session, *registryId, *region)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	for _, data := range authToken.AuthorizationData {
		output, err := base64.StdEncoding.DecodeString(*data.AuthorizationToken)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		split := strings.Split(string(output), ":")
		if len(split) == 2 {
			token = strings.TrimSpace(split[1])
		} else {
			fmt.Println("failed to parse token")
			os.Exit(1)
		}
	}
	if token == "" {
		fmt.Println("password was empty")
		os.Exit(1)
	}
	fmt.Printf("%s", token)
}

func getAssumedSession(roleArn, externalId, region string) (*session.Session, error) {
	initSession := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))
	awsSts := sts.New(initSession)
	sessionName := fmt.Sprintf("spinnakerManagedEcr-%d", rand.Int())
	assumedRole, err := awsSts.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(sessionName),
		ExternalId:  aws.String(externalId),
	})
	if err != nil {
		return nil, err
	}
	return session.NewSession(&aws.Config{
		Credentials:   credentials.NewStaticCredentials(
			*assumedRole.Credentials.AccessKeyId,
			*assumedRole.Credentials.SecretAccessKey,
			*assumedRole.Credentials.SessionToken),
		Region:        aws.String(region),
	})
}

func getEcrToken(session *session.Session, registry, region string) (*ecr.GetAuthorizationTokenOutput, error) {
	ecrClient := ecr.New(session, &aws.Config{
		Region: aws.String(region),
	})
	inputAuthToken := &ecr.GetAuthorizationTokenInput{
		RegistryIds: []*string{aws.String(registry)},
	}
	authToken, err := ecrClient.GetAuthorizationToken(inputAuthToken)
	if err != nil {
		return nil, err
	}
	return authToken, nil
}
