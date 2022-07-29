package factories

import (
	"fmt"

	"github.com/bluele/factory-go/factory"
	"github.com/brianvoe/gofakeit"
	"github.com/mysocketio/mysocketctl-go/internal/api/models"
)

var SocketFactory = factory.NewFactory(
	&models.Socket{
		TargetHostname:        "webserver.connector.lab",
		TargetPort:            8000,
		Name:                  "webserver.connector.lab",
		SocketType:            "http",
		AllowedEmailAddresses: []string{"some-email01@domain.com"},
		AllowedEmailDomains:   []string{"mysocket.io", "some-other-domain.com"},
	},
).Attr("SocketID", func(args factory.Args) (interface{}, error) {
	return gofakeit.UUID(), nil
}).Attr("Name", func(args factory.Args) (interface{}, error) {
	return fmt.Sprintf("random-flower-%v", gofakeit.Number(1, 100)), nil
}).Attr("TargetHostname", func(args factory.Args) (interface{}, error) {
	return fmt.Sprintf("random-flower-%v", gofakeit.Number(1, 100)), nil
}).Attr("SocketType", func(args factory.Args) (interface{}, error) {
	return "http", nil
}).Attr("TargetPort", func(args factory.Args) (interface{}, error) {
	return 8080, nil
}).Attr("UpstreamType", func(args factory.Args) (interface{}, error) {
	return "http", nil
})
