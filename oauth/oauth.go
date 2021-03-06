package oauth

import (
	"encoding/json"
	"fmt"
	common_errors "github.com/gpankaj/common-go-oauth/common-errors"
	"github.com/mercadolibre/golang-restclient/rest"
	"log"
	"net/http"
	"strconv"
	"strings"
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
		log.Println("Checking if header is public but request object is null")
		return true
	}
	if r.Header.Get(headerXPublic)=="" && r.Header.Get(headerXPublic) == "true" {
		return true
	}
	return false
}

func GetClientId(r *http.Request) int64{
	if r == nil {
		return 0
	}
	//clientId , err := strconv.ParseInt(r.Header.Get(headerXClientId),10,64)
	clientId , err := strconv.Atoi(r.Header.Get(headerXClientId))
	log.Println("Client id in GetClientId ", clientId)

	if err != nil {
		log.Println("Hit an issue during conversion from str to int in GetClientId ", err.Error())
		return 0
	}

	return int64(clientId)
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

	println("Header is ==================")

	if r == nil {
		return nil
	}
	cleanRequest(r)
	//api.shiftinghub.com/resource?access_token=abc123
	accessTokenFromParam := strings.TrimSpace(r.URL.Query().Get(paramAccessToken))
	if accessTokenFromParam == "" {
		log.Println("Returing because accessTokenFromParam is empty")
		return nil
	}


	oauthTokenStructAsInstance, err := getAccessToken(accessTokenFromParam)
	if err != nil {
		if err.Code == http.StatusNotFound {
			log.Println("Error ", err.Code)
			return common_errors.NewInternalServerError("Access token error "+ err.Message)
		}
		return err
	}

	log.Println("User_id from instaance of oauthTokenStructAsInstance is ", oauthTokenStructAsInstance.User_id)

	log.Println("Id from instance of oauthTokenStructAsInstance is ", oauthTokenStructAsInstance.Id);

	r.Header.Add(headerXClientId,fmt.Sprintf("%v",oauthTokenStructAsInstance.User_id))
	r.Header.Add(headerXCallerId,fmt.Sprintf("%v",oauthTokenStructAsInstance.Id))
	r.Header.Add(headerXPublic,"false")

	log.Println("headerXClientId ==> " ,r.Header.Values(headerXClientId))

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
	log.Println("Token inside getAccessToken ",tokenId );

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
	log.Println("inside getAccessToken User_id ", oauthTokenStructAsInstance.User_id)
	return &oauthTokenStructAsInstance, nil
}