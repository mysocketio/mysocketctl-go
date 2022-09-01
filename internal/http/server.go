package http

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"

	jwt "github.com/golang-jwt/jwt"
)

func renderResponse(header http.Header, hostName string, adminName string, adminEmail string) string {

	return fmt.Sprintf(`
 	<!DOCTYPE html>
	<head>
		<title>Welcome to Border0</title>
		<style>
			body {
				background-color: #2D2D2D;
			}
			
			h1 {
				color: #C26356;
				font-size: 30px;
				font-family: Menlo, Monaco, fixed-width;
			}
			
			p {
				color: white;
				font-family: "Source Code Pro", Menlo, Monaco, fixed-width;
			}
			a {
				color: white;
				font-family: "Source Code Pro", Menlo, Monaco, fixed-width;
			  }
		</style>
	</head>
	<body>
		<h1>🚀 Welcome to the Border0 built-in webserver</h1>
		
		<p>Hi and welcome %s (%s)!<br><br>
		You're visiting the built-in Border0 webserver, this web service was started by the administrator of this Border0 Organizaton: <br><i><u>%s (%s)</u></i> <br><br>

		You can now start to make your own web, ssh or database applications available through Border0. <br><br>
		Check out the documentation for more information: <a href='https://docs.border0.com'>https://docs.border0.com</a></p>
		</p>
		<p> <br><br>
		
		Have a great day! 😊 🚀 <br><br>
		(you're visiting %s from IP %s) 
		</p>
	</body>
	</html>
	`, header["X-Auth-Name"][0], header["X-Auth-Email"][0], adminName, adminEmail, hostName, header["X-Real-Ip"][0])

}
func StartLocalHTTPServer(dir string, l net.Listener) error {

	if dir == "" {

		// Get Org admin info
		adminName := "Unknown"
		adminEmail := "Unknown"

		admindata, err := getAdminData()
		if err != nil {
			fmt.Println("Warning: Could not get admin data: name", err)
		} else {
			if _email, ok := admindata["user_email"].(string); ok {
				adminEmail = _email

			} else {
				fmt.Println("Warning: Could not get admin data: email")

			}
			if _name, ok := admindata["name"].(string); ok {
				adminName = _name
			} else {
				fmt.Println("Warning: Could not get admin data: name")
			}

		}

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

			fmt.Fprintf(w, renderResponse(r.Header, r.Host, adminName, adminEmail))
		})

		err = http.Serve(l, nil)

		if err != nil {
			return err
		}

		return nil
	} else {
		fs := http.FileServer(http.Dir(dir))
		http.Handle("/", http.StripPrefix("/", fs))
	}

	err := http.Serve(l, nil)
	if err != nil {
		return err
	}

	return nil
}

func getToken() (string, error) {
	if _, err := os.Stat(tokenfile()); os.IsNotExist(err) {
		return "", errors.New("please login first (no token found)")
	}
	content, err := ioutil.ReadFile(tokenfile())
	if err != nil {
		return "", err
	}

	tokenString := strings.TrimRight(string(content), "\n")
	return tokenString, nil
}

func getAdminData() (jwt.MapClaims, error) {
	admintoken, err := GetToken()
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse(admintoken, nil)
	if token == nil {
		return nil, err
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	return claims, nil
}
