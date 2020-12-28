package common_errors


import "net/http"

type RestErr struct {
	Message string
	Code int
	Error string
}

func NewBadRequestError(message string)(*RestErr) {
	return &RestErr{
		Message: message,
		Code: http.StatusBadRequest,
		Error: "Bad_Request",
	}
}



func NewNotFoundError(message string)(*RestErr) {
	return &RestErr{
		Message: message,
		Code: http.StatusNotFound,
		Error: "not_found",
	}
}


func NewInternalServerError(message string) (*RestErr){
	return &RestErr{
		Message: message,
		Code: http.StatusInternalServerError,
		Error: "internal_server_error",
	}
}

func NewUniqueContraintViolationcompany_name_listing_active_uniqueError(message string) (*RestErr) {
	return &RestErr{
		Message: message,
		Code: http.StatusBadRequest,
		Error: "bad_request",
	}
}
