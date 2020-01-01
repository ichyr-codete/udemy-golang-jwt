package controllers

import "net/http"

// ProtectedEndpoint ...
func (c *Controller) ProtectedEndpoint() http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("/protected endpoint hit"))
	}
}
