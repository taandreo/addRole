package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/exp/slices"
)

var subscriptionId string
var scopeFile string
var roleFile string
var principalId string
var ctx context.Context

func main() {
	flag.StringVar(&subscriptionId, "subscriptionId", "", "subscriptionId where the resources are located")
	flag.StringVar(&scopeFile, "scopeFile", "", "ResourceId for the resource")
	flag.StringVar(&roleFile, "roleFile", "", "ResourceId for the resource")
	flag.StringVar(&principalId, "principalId", "", "principalId")
	flag.Parse()
	ctx = context.Background()
	if subscriptionId == "" {
		error("-subscriptionId parameter must be informed")
	}
	if scopeFile == "" {
		error("-scope parameter must be informed")
	}
	if roleFile == "" {
		error("-roleFile must be informed")
	}
	roles := readLines(roleFile)
	scopes := readLines(scopeFile)
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		error(err.Error())
	}
	clientOptions := azcore.ClientOptions{
		APIVersion: "2022-04-01",
	}
	assignClient, err := armauthorization.NewRoleAssignmentsClient(subscriptionId, cred, &policy.ClientOptions{ClientOptions: clientOptions})
	if err != nil {
		error(err.Error())
	}
	rolesIds := getRolesFromScope(roles, scopes[0], cred)
	for roleName, roleId := range rolesIds {
		for _, scope := range scopes {
			fmt.Printf("Given permission for identity %s in %s with role %s\n", principalId, scope, roleName)
			assignRole(roleId, principalId, scope, assignClient)
		}
	}
}

func assignRole(roleId string, principalId string, scope string, client *armauthorization.RoleAssignmentsClient) {
	guid := uuid.NewV4()
	_, err := client.Create(ctx,
		scope,
		guid.String(),
		armauthorization.RoleAssignmentCreateParameters{
			Properties: &armauthorization.RoleAssignmentProperties{
				PrincipalID:      &principalId,
				RoleDefinitionID: &roleId,
			},
		},
		nil,
	)
	if err != nil {
		line := grep(err.Error(), "ERROR CODE")
		fmt.Fprintln(os.Stderr, line)
	}
}

func grep(text string, searchTerm string) string {
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		if strings.Contains(line, searchTerm) {
			return line
		}
	}
	return ""
}

func readLines(file string) []string {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		error(err.Error())
	}
	roles := strings.Split(string(data), "\n")
	return roles
}

func getRolesFromScope(roles []string, scope string, cred azcore.TokenCredential) map[string]string {
	ids := make(map[string]string)
	client, _ := armauthorization.NewRoleDefinitionsClient(cred, nil)
	pager := client.NewListPager(scope, nil)
	for pager.More() {
		nextResult, err := pager.NextPage(ctx)
		if err != nil {
			error(err.Error())
		}
		for _, v := range nextResult.Value {
			if slices.Contains(roles, *v.Properties.RoleName) {
				ids[*v.Properties.RoleName] = *v.ID
			}
		}
	}
	for _, roleName := range roles {
		_, exist := ids[roleName]
		if !exist {
			error("Role " + roleName + " not found.")
		}
	}
	return ids
}

func error(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
