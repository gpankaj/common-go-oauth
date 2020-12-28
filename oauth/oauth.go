package oauth

import (
	"encoding/json"
	"fmt"
	common_errors "github.com/gpankaj/common-go-oauth/common-errors"
	"net/http"
	"strconv"
	"strings"
	"github.com/mercadolibre/golang-restclient/rest"
	"time"
)
var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:9090",
		Timeout: 200*time.Millisecond,
	}
)
//private struct
type oauthTokenStructAsClass struct {
	Id string //User id from db
	User_id int64 //Caller Id
	Client_id int64 //Mac or Andoid or ..
}

//Private interface
//type oauthInterface interface { }
const (
	headerXPublic = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	//Param is not same as header.
	paramAccessToken = "access_token"
)
func IsPublic(r *http.Request) bool {
	if r == nil {
		return true
	}
	if r.Header.Get(headerXPublic) != "true" || r.Header.Get(headerXPublic) != "false" {
		return true
	}
	if r.Header.Get(headerXPublic) == "true"{
		return true
	}
	return false
}

func GetClientId(r *http.Request) int64{
	if r == nil {
		return 0
	}
	clientId , err := strconv.ParseInt(r.Header.Get(headerXClientId),10,64)
	if err == nil {
		return 0
	}
	return clientId
}

func GetCallerId(r *http.Request) int64 {
	if r == nil {
		return 0
	}
	callerId , err := strconv.ParseInt(r.Header.Get(headerXCallerId),10,64)
	if err == nil {
		return 0
	}
	return callerId
}

func AuthenticateRequest(r *http.Request) *common_errors.RestErr{
	if r == nil {
		return nil
	}
	cleanRequest(r)
	//api.shiftinghub.com/resource?access_token=abc123
	accessTokenFromParam := strings.TrimSpace(r.URL.Query().Get(paramAccessToken))
	if accessTokenFromParam == "" {
		return nil
	}


	oauthTokenStructAsInstance, err := getAccessToken(accessTokenFromParam)
	if err != nil {
		if err.Code == http.StatusNotFound {
			return nil
		}
		return err
	}

	r.Header.Add(headerXClientId,fmt.Sprintf("%v",oauthTokenStructAsInstance.Id))
	r.Header.Add(headerXCallerId,fmt.Sprintf("%v",oauthTokenStructAsInstance.User_id))
	return nil
}

func cleanRequest(r *http.Request) {
	if r == nil {
		return
	}
	r.Header.Del(headerXClientId)
	r.Header.Del(headerXCallerId)
}

func getAccessToken(tokenId string) (*oauthTokenStructAsClass, *common_errors.RestErr) {
	response:=oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", tokenId))
	if response == nil || response.Response == nil  { //Timeout situation.
		return nil, common_errors.NewInternalServerError("invalid restClientRequest when trying to get access token")
	}

	if response.StatusCode > 299 { //Means we have an error situation.
		var restError common_errors.RestErr
		err := json.Unmarshal(response.Bytes(), &restError)
		if err!= nil {
			return nil, common_errors.NewInternalServerError("invalid error interface, when trying to get access token")
		}
		return nil, &restError
	}

	var oauthTokenStructAsInstance oauthTokenStructAsClass

	if err := json.Unmarshal(response.Bytes(), &oauthTokenStructAsInstance); err!=nil {
		return nil, common_errors.NewInternalServerError("Mismatch in signature of access token response")
	}
	return &oauthTokenStructAsInstance, nil
}